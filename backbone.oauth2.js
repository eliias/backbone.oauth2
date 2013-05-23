/*!
 * oauth2.js v0.2.1
 * Copyright 2013, Hannes Moser (@eliias)
 */
define(['jquery', 'jstorage', 'underscore', 'backbone'],
function($, jstorage, _, Backbone) {

    /**
     * The key used for localStorage
     *
     * @type String
     */
    var STORAGE_KEY = '__oauth2';

    /**
     * The interval between two checks if token expires
     * Default value is 60000 ms = 1 minute
     *
     * @type Number Time in ms
     */
    var AUTO_REFRESH_TIME = 60000;

    /**
     * The maximum time before an access_token must be renewed
     * Default value is 600 secs = 10 minutes
     *
     * @type Number Time in seconds
     */
    var REFRESH_MAX_TIME = 600;

    /**
     * Backbone.OAuth2 object
     *
     * @type Backbone.OAuth2
     */
    var OAuth2 = Backbone.OAuth2 = function(options) {
        options = _.extend({
            accessUrl:      'https://api.tld/v2/oauth/access',
            refreshUrl:     'https://api.tld/v2/oauth/refresh',
            revokeUrl:      'https://api.tld/v2/oauth/revoke',
            autoRefresh:    true
        }, options);
        if (options.accessUrl)      this.accessUrl      = options.accessUrl;
        if (options.refreshUrl)     this.refreshUrl     = options.refreshUrl;
        if (options.revokeUrl)      this.revokeUrl      = options.revokeUrl;
        if (options.grantType)      this.grantType      = options.grantType;
        if (options.clientId)       this.clientId       = options.clientId;
        if (options.clientSecret)   this.clientSecret   = options.clientSecret;

        // Store previous authentications
        Backbone.OAuth2.state = load();

        /**
         * If autorefresh is enabled, check expiration date of access_token
         * every second.
         */
        if(options.autoRefresh) {
            var self = this;
            var triggerRefresh = function(auth) {
                if(OAuth2.isAuthenticated()) {
                    if(OAuth2.expiresIn() < REFRESH_MAX_TIME) {
                        console.info('A new access-token/refresh-token has been requested.');
                        auth.refresh();
                    }
                    setTimeout(triggerRefresh, AUTO_REFRESH_TIME, auth);
                }
            };
            setTimeout(triggerRefresh, AUTO_REFRESH_TIME, self);
        }

        // Invoke initialize method
        this.initialize.apply(this, arguments);
    };

    /**
     * Set current state object to null. This object is later used to
     * store the last response object from either an valid or invalid
     * authentication attempt.
     *
     * Example:
     * {
     *   "access_token": "52d8670532483516dbe1dfc55d3de2b148b63995",
     *   "expires_in": "2419200",
     *   "token_type": "bearer",
     *   "scope": null,
     *   "time": null,
     *   "refresh_token": "be4b157c57bfbd79f0183b9ebd7879326d080ad8"
     * }
     *
     * @type {object}
     */
    OAuth2.state = null;

    /**
     * Verify if the current state is "authenticated".
     *
     * @returns {Boolean}
     */
    OAuth2.isAuthenticated = function() {
        // Store previous authentications
        Backbone.OAuth2.state = load();

        var state = OAuth2.state;
        var time = new Date().getTime();
        if(typeof state !== 'undefined' && state !== null) {
            // Check if token has already expired
            if(parseInt(state.expires_in) + state.time > time) {
                return true;
            }
        }

        return false;
    };

    /**
     * Get epxiration time for the access-token. This method should be used to
     * request a new accessToken automatically after 50% of the access-token
     * lifetime. This method always returns a positive integer or -1 if not
     * authenticated.
     *
     * @returns {int} Seconds until access-token will expire
     */
    OAuth2.expiresIn = function() {
        if(OAuth2.isAuthenticated()) {
            var time = new Date().getTime();
            var state = OAuth2.state;
            return (state.time + parseInt(state.expires_in)) - time;
        }
        return -1;
    };

    /**
     * Setup all inheritable <strong>Backbone.OAuth2</strong> properties and methods.
     */
    _.extend(OAuth2.prototype, Backbone.Events, {
        /**
         * Initialize is an empty function by default. Override it with your
         * own initialization logic.
         *
         * @returns {void}
         */
        initialize: function() {},

        /**
         * Authenticates against an OAuth2 endpoint
         *
         * @param {string} username
         * @param {string} password
         * @returns {void}
         */
        access: function(username, password) {
            // Store a reference to the object
            var self = this;

            // Check if we have already authenticated
            if(Backbone.OAuth2.isAuthenticated()) {
                // Trigger success event
                self.trigger('success', Backbone.OAuth2.state, this);

                // Return early
                return;
            }

            /*
             * Save time before request to avoid race conditions with expiration
             * timestamps
             */
            var time = new Date().getTime();

            // Request a new access-token/refresh-token
            $.ajax({
                url: self.accessUrl,
                type: 'POST',
                data: {
                    grant_type:     'password',
                    client_id:      self.clientId,
                    client_secret:  self.clientSecret,
                    username:       username,
                    password:       password
                },
                dataType: "json",

                /**
                 * Success event, triggered on every successfull
                 * authentication attempt.
                 *
                 * @param {object} response
                 * @returns {void}
                 */
                success: function(response) {
                    // Extend response object with current time
                    response.time = time;

                    // Get timediff before and after request for localStorage
                    var timediff = new Date().getTime() - time;

                    // Store response object as Backbone.OAuth2 property
                    Backbone.OAuth2.state = response;

                    // Store to localStorage too(faster access)
                    save(response, response.expires_in - timediff);

                    // Trigger success event
                    self.trigger('success', response, this);
                },

                /**
                 * Error event, triggered on every failed authentication attempt.
                 *
                 * @param {object} response
                 * @returns {void}
                 */
                error: function(response) {
                    // If authenticated, try to refresh before throwing an error
                    self.refresh();

                    // Trigger error event
                    self.trigger('error', response, this);
                }
            });
        },

        /**
         * Request a new access_token and request_token by sending a valid
         * refresh_token
         * @returns {void}
         */
        refresh: function() {
            // Store a reference to the object
            var self = this;

            // Check if we are already authenticated
            if(load()) {
                // Store response object as Backbone.OAuth2 property
                Backbone.OAuth2.state = load();
            } else {
                self.trigger(
                    'error',
                    'No authentication data found, please use the access method first.',
                    this);
            }

            /*
             * Save time before request to avoid race conditions with expiration
             * timestamps
             */
            var time = new Date().getTime();

            // Request a new access-token/refresh-token
            $.ajax({
                url: self.refreshUrl,
                type: 'POST',
                data: {
                    grant_type:     'refresh_token',
                    client_id:      self.clientId,
                    client_secret:  self.clientSecret,
                    refresh_token:  OAuth2.state.refresh_token
                },
                dataType: "json",

                /**
                 * Success event, triggered on every successfull
                 * authentication attempt.
                 *
                 * @param {object} response
                 * @returns {void}
                 */
                success: function(response) {
                    // Extend response object with current time
                    response.time = time;

                    // Get timediff before and after request for localStorage
                    var timediff = new Date().getTime() - time;

                    // Store response object as Backbone.OAuth2 property
                    Backbone.OAuth2.state = response;

                    // Store to localStorage too(faster access)
                    save(response, response.expires_in - timediff);

                    // Trigger success event
                    self.trigger('success', response, this);
                },

                /**
                 * Error event, triggered on every failed authentication attempt.
                 *
                 * @param {object} response
                 * @returns {void}
                 */
                error: function(response) {
                    // Trigger error event
                    self.trigger('error', response, this);
                }
            });
        },

        /**
         * Revoke OAuth2 access if a valid token exists and clears related
         * properties (access_token, refresh_token)
         * @returns {void}
         */
        revoke: function() {
            // Store a reference to the object
            var self = this;

            /*
             * If we are not authenticated, just clear state property
             */
            if(!OAuth2.isAuthenticated()) {
                // Clear localStorage (if set)
                clear();

                // Set state to null
                OAuth2.state = null;

                // Trigger revoke event
                self.trigger('revoke', null, this);

                // Return early
                return;
            }

            // Build header
            var state = Backbone.OAuth2.state;
            var tokenType = capitalize(state.token_type);
            var accessToken = state.access_token;

            // Request a new access-token/refresh-token
            $.ajax({
                url: self.revokeUrl,
                type: 'POST',
                data: {
                    token:           Backbone.OAuth2.state.access_token,
                    token_type_hint: 'access_token'
                },
                headers: {
                    "Authorization": tokenType + ' ' + accessToken
                },

                /**
                 * Success event, triggered on every successfull
                 * revokation attempt.
                 *
                 * @param {object} response
                 * @returns {void}
                 */
                success: function(response) {
                    // Delete the key
                    clear();

                    // Trigger revoke event
                    self.trigger('revoke', response, this);
                },

                /**
                 * Error event, triggered on every failed authentication attempt.
                 *
                 * @param {object} response
                 * @returns {void}
                 */
                error: function(xhr, ajaxOptions, thrownError) {
                    /*
                     * Check if 401 Not Authorized is returned
                     */
                    if(xhr.status == 401) {
                        // Delete the key
                        clear();

                        // Trigger error event
                        self.trigger('revoke', xhr, this);
                    }

                    // Trigger error event
                    self.trigger('error', xhr, this);
                }
            });
        }
    });

    /**
     * Store the original sync method for later use
     *
     * @type @exp;Backbone@pro;sync
     */
    var sync = Backbone.sync;

    /**
     * Capitalizes a string
     *
     * @param {string} str
     * @returns {string}
     */
    var capitalize = function(str) {
        return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
    };

    /**
     * Get value for STORAGE_KEY from localStorage
     * @returns {object,boolean}
     */
    var load = function() {
        return $.jStorage.get(STORAGE_KEY, false);
    };

    /**
     * Save state with STORAGE_KEY to localStorage and set ttl
     * @param {object} state
     * @returns {void}
     */
    var save = function(state, ttl) {
        $.jStorage.set(STORAGE_KEY, state);
        $.jStorage.setTTL(STORAGE_KEY, ttl);
    };

    /**
     * Clear value assigned to STORAGE_KEY from localStorage
     * @returns {void}
     */
    var clear = function() {
        var key = $.jStorage.get(STORAGE_KEY, false);
        if(key) {
            $.jStorage.deleteKey(STORAGE_KEY);
        }
    };

    /**
     * Override Backbone.sync for all future requests
     * @param {string} method
     * @param {Backbone.Model} model
     * @param {object} options
     * @returns {Backbone}
     */
    Backbone.sync = function(method, model, options) {
        if(Backbone.OAuth2.isAuthenticated()) {
            var state = Backbone.OAuth2.state;
            var tokenType = capitalize(state.token_type);
            var accessToken = state.access_token;
            options.headers = options.headers || {};
            _.extend(options.headers, { 'Authorization': tokenType + ' ' + accessToken });
        }

        return sync.call(model, method, model, options);
    };

    /**
     * Setup inheritance
     */
    OAuth2.extend = Backbone.History.extend;

});
