/*
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthias Schmidt <matthias@dragonflybsd.org>, University of Marburg,
 * Germany.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <grp.h>

#include "dma.h"

#define DP	": \t"
#define EQS	" \t"

/* Declarations of "private" types */

typedef int (*check_ptr_t)(const char*, const char*);
struct config_item_t {
        check_ptr_t checkFunction;
        char *identifier;
        char *str_value;
        bool boolean_flag;
        SLIST_ENTRY(config_item_t) next_item;
};
SLIST_HEAD( S_CONFIGHEAD, config_item_t);

struct authuser {
        SLIST_ENTRY(authuser) next;
        char *login;
        char *password;
        char *host;
};
SLIST_HEAD( authusers, authuser);

/* Initializations */

struct S_CONFIGHEAD config_head = SLIST_HEAD_INITIALIZER(config_head);
struct authusers authusers = LIST_HEAD_INITIALIZER(authusers);
bool is_configuration_initialized = false;

struct config_item_t *last_checked_item = NULL;

/* Static function declarations
 * they are "private" (internal linkage) */

static int check_fingerprint_configuration(const char*, const char*);
static int check_nullclient_configuration(const char*, const char*);
static void initialize_configuration_setting(const char*, check_ptr_t, bool,
                                             const char*);
static int check_mailname_configuration(const char*, const char*);

/* Debug Configuration */

/*#define DEBUG_CONF*/

#ifdef DEBUG_CONF
static void print_configuration_settings(void);
static void print_auth_items(void);
static void print_masquerade_settings(void);
#endif

/*
 * Remove trailing \n's
 */
void
trim_line(char *line)
{
        size_t linelen;
        char *p;

        if ((p = strchr(line, '\n')))
                *p = (char) 0;

        /* Escape leading dot in every case */
        linelen = strlen(line);
        if (line[0] == '.') {
                if ((linelen + 2) > 1000) {
                        syslog(LOG_CRIT, "Cannot escape leading dot.  Buffer overflow");
                        exit(EX_DATAERR);
                }
                memmove((line + 1), line, (linelen + 1));
                line[0] = '.';
        }
}

/*
 * Read the SMTP authentication config file
 *
 * file format is:
 * user|host:password
 *
 * A line starting with # is treated as comment and ignored.
 */
void
parse_authfile(const char *path)
{
        struct stat statbuffer;
        struct group *group;

        auth_in = fopen(path, "r");
        if (auth_in == NULL) {
                errlog(EX_NOINPUT, "can not open auth file `%s'", path);
                /* NOTREACHED */
        }

        if (auth_parse())
                errlog(EX_CONFIG, "syntax error in authfile '%s'", path);

        /*
         * Since the user is supposed to supply his user details in plain text
         * we should check if the file containing this data is not world-readable
         * and has the correct owners.
         * We will still continue processing the mail in case
         * the checks are not passed, but emit an informational warning message.
         */
        if(fstat(fileno(auth_in), &statbuffer) == 0) {
                /* Check file permissions
                 * we only care about the world permissions
                 */
                if((statbuffer.st_mode & S_IRWXO) != 0)
                        log_warning("Auth file '%s': File permissions are %o whereas 640 is recommended. "
                                        "Thus, your passwords may be readable by others.",
                                        path, statbuffer.st_mode & 0777);
                group = getgrnam(DMA_GROUP);

                if(group != NULL) {
                        if(statbuffer.st_uid != 0 || group->gr_gid != statbuffer.st_gid)
                                log_warning("Auth file '%s': Incorrect owners. "
                                                "Should be '%s' with group '%s'.",
                                                path, "root", DMA_GROUP);
                }
        }

        fclose(auth_in);

#ifdef DEBUG_CONF
        print_auth_items();
#endif
}

void
parse_conf(const char *config_path)
{
        if (!is_configuration_initialized)
                errlogx(EX_SOFTWARE,
                                "parse_conf must be run after initialize_all_configuration_settings()");

        conf_in = fopen(config_path, "r");
        if (conf_in == NULL) {
                /* Don't treat a non-existing config file as error */
                if (errno == ENOENT)
                        return;
                errlog(EX_NOINPUT, "can not open config `%s'", config_path);
                /* NOTREACHED */
        }
        if (conf_parse())
                errlogx(EX_CONFIG, "Syntax error in config file '%s'", config_path);

        fclose(conf_in);

        /* NULLCLIENT configuration can only be checked once all config entries have been parsed */
        if (is_configuration_setting_enabled(CONF_NULLCLIENT)) {
                if (check_nullclient_configuration(CONF_NULLCLIENT, NULL) != 0)
                        errlogx(EX_CONFIG, "%s: NULLCLIENT requires SMARTHOST",
                                        config_path);
        }

#ifdef DEBUG_CONF
        print_configuration_settings();
        print_masquerade_settings();
#endif
}

/*
 * Function that sets up all configuration settings that are known to the program
 * Shall be run on startup. Runs only once.
 * Any new configuration settings must be entered in this function according to the
 * syntax of initialize_configuration_setting
 */
void
initialize_all_configuration_settings(void)
{
        if (is_configuration_initialized) {
                /* This function shall only run once... */
                return;
        }

        is_configuration_initialized = true;

        SLIST_INIT(&config_head);

        /* Settings */
        initialize_configuration_setting(CONF_SMARTHOST, NULL, false, NULL);
        initialize_configuration_setting(CONF_PORT, NULL, false, SMTP_PORT_STRING);
        initialize_configuration_setting(CONF_ALIASES, NULL, false,
                                         DEFAULT_ALIASES_PATH);
        initialize_configuration_setting(CONF_SPOOLDIR, NULL, false, DEFAULT_SPOOLDIR);
        initialize_configuration_setting(CONF_AUTHPATH, NULL, false, NULL);
        initialize_configuration_setting(CONF_CERTFILE, NULL, false, NULL);
        initialize_configuration_setting(CONF_MAILNAME, &check_mailname_configuration, false, NULL);
        initialize_configuration_setting(CONF_MASQUERADE, NULL, false, NULL);
        initialize_configuration_setting(CONF_STARTTLS, NULL, true, NULL);
        initialize_configuration_setting(CONF_FINGERPRINT,
                                         &check_fingerprint_configuration, false, NULL);
        initialize_configuration_setting(CONF_TLS_OPP, NULL, true, NULL);
        initialize_configuration_setting(CONF_SECURETRANSFER, NULL, true, NULL);
        initialize_configuration_setting(CONF_DEFER, NULL, true, NULL);
        initialize_configuration_setting(CONF_INSECURE, NULL, true, NULL);
        initialize_configuration_setting(CONF_FULLBOUNCE, NULL, true, NULL);
        initialize_configuration_setting(CONF_NULLCLIENT, NULL, true, NULL);
}

/*
 * Sets up one configuration setting
 * Shall only be called by initialize_all_configuration_settings()
 *
 * Parameters
 * identifier: The name of the parameter
 * func_ptr: (An address to) a function that verifies the entered data
 *           as an example refer to the check_mailname_configuration function
 *           can be NULL if there's no function to be called
 * is_boolean_flag: Specifies whether the configuration setting needs a value to be provided
 *                  true if no value is needed (for example for the STARTTLS flag)
 * default_value: Any pre-set value for the configuration setting (NULL if there's none)
 */
static void
initialize_configuration_setting(const char *identifier,
                                             check_ptr_t func_ptr,
                                             bool is_boolean_flag,
                                             const char *default_value)
{
        struct config_item_t *item;

        if (identifier == NULL)
                return;

        /* Check if the setting has already been initialized */
        SLIST_FOREACH(item, &config_head, next_item) {
                if (strcmp(identifier, item->identifier) == 0) {
                        /* Already in list */
                        errlogx(EX_SOFTWARE, "Trying to initialize setting '%s' more than once",
                                        identifier);
                }
        }

        item = calloc(1, sizeof(struct config_item_t));
        if (item == NULL)
                errlog(EX_OSERR, "Error allocating memory\n");

        /* We use strdup() here so that we'll be able to properly clean up everything */
        item->identifier = strdup(identifier);
        item->checkFunction = func_ptr;
        item->boolean_flag = is_boolean_flag;

        if (default_value != NULL)
                item->str_value = strdup(default_value);
        else
                item->str_value = NULL;

        SLIST_INSERT_HEAD(&config_head, item, next_item);
}

/*
 * Called by yacc-generated parser code, do not call from anywhere else.
 * Checks, if a configuration setting is known to the program
 * If so, checks the value and calls an existing check function
 * that is associated with a configuration setting.
 * Returns non-zero on error (mostly unknown identifiers or invalid values)
 */
int
try_to_set_configuration_setting(char *identifier, char *value)
{
        struct config_item_t *item = NULL;
        bool found = false;

        SLIST_FOREACH(item, &config_head, next_item)
                if (strcmp(identifier, item->identifier) == 0) {
                        found = true;
                        break;
                }

        if (found) {
                /*
                 * item is pointing to the correct item now
                 * Let's see if it requires a value
                 */
                if (!item->boolean_flag) {
                        /* Check values */
                        if (value == NULL)
                                /* Item requires a value, but no value has been provided! */
                                return (EX_CONFIG);

                        /* Call the check function, if it exists */
                        if (item->checkFunction != NULL)
                                if (item->checkFunction(identifier, value) != 0)
                                        return (EX_CONFIG);

                        /* Else let's store the value and return */
                        if (item->str_value != NULL)
                                free(item->str_value); /* Let's free the old value first */

                        item->str_value = value;
                        return (0);
                } else {
                        /*
                         * No value needed
                         * Check if a value has been provided even though no value is expected
                         */
                        if (value != NULL)
                                return (EX_CONFIG);

                        if (item->checkFunction != NULL)
                                if (item->checkFunction(identifier, value) != 0)
                                        return (EX_CONFIG);

                        /*
                         * else let's set the config flag to on
                         * we do not bother changing the value if it is already set,
                         * as its concrete value is meaningless.
                         * The value can already be set,
                         * if its flag has been enabled more than once in the config file.
                         */
                        if (item->str_value == NULL)
                                item->str_value = strdup("ON");
                        return (0);
                }
        } else {
                /* Item has not been found */
                return (EX_CONFIG);
        }
}

static int check_fingerprint_configuration(const char *identifier,
                                           const char *value)
{
        unsigned int counter;
        unsigned char *fingerprint;

        if (identifier == NULL || value == NULL)
                return (EX_CONFIG);

        if (strlen(value) != SHA256_DIGEST_LENGTH * 2)
                return (EX_CONFIG);

        fingerprint = malloc(SHA256_DIGEST_LENGTH);
        if (fingerprint == NULL)
                return (EX_OSERR);

        for (counter = 0; counter < SHA256_DIGEST_LENGTH; counter++) {
                if (sscanf(value + 2 * counter, "%02hhx", &fingerprint[counter]) != 1) {
                        free(fingerprint);
                        return (EX_CONFIG);
                }
        }

        free(fingerprint);
        return (0);
}

/* Helper function to return the masquerade settings split up in login and host */
struct masquerade_config_t*
extract_masquerade_settings(const char *value)
{
        char *user;
        char *host;
        char *copy_of_value;

        struct masquerade_config_t *masquerade;

        copy_of_value = host = user = NULL;

        if (value == NULL)
                return (NULL);

        masquerade = malloc(sizeof(struct masquerade_config_t));

        if (masquerade == NULL)
                return (NULL);

        copy_of_value = strdup(value);

        if (copy_of_value == NULL) {
                free(masquerade);
                return (NULL);
        }

        host = strrchr(copy_of_value, '@');
        if (host != NULL) {
                *host = '\0';
                host++;
                user = copy_of_value;
        } else {
                host = copy_of_value;
        }

        if (host != NULL && *host == '\0')
                host = NULL;
        if (user != NULL && *user == '\0')
                user = NULL;

        if (host != NULL)
                masquerade->host = strdup(host);
        else
                masquerade->host = NULL;

        if (user != NULL)
                masquerade->user = strdup(user);
        else
                masquerade->user = NULL;

#ifdef DEBUG_CONF
        printf("masquerade_config.host: '%s'\tmasquerade_config.user: '%s'\n",
                        masquerade->host, masquerade->user);
#endif

        free(copy_of_value);
        return (masquerade);
}

static int
check_nullclient_configuration(const char *identifier,
                                          const char *value)
{
        if (identifier == NULL || value != NULL)
                errlogx(EX_SOFTWARE,
                                "checkNullClientConfiguration called with invalid arguments.");

        if (is_configuration_setting_enabled(CONF_SMARTHOST))
                return (0);

        /* NULLCLIENT requires SMARTHOST */
        return (EX_CONFIG);
}

bool
is_configuration_setting_enabled(const char *identifier)
{
        struct config_item_t *item;

        if (identifier == NULL)
                return (false);

        SLIST_FOREACH(item, &config_head, next_item) {
                if (strcmp(identifier, item->identifier) == 0) {
                        /* Found the setting */
                        if (!item->boolean_flag) {
                                if (item->str_value != NULL) {
                                        last_checked_item = item;
                                        /* Pointer to the last item that was queried
                                         * this is subsequently checked first,
                                         * if get_configuration_value() is called */
                                        return (true);
                                } else {
                                        return (false);
                                }
                        } else {
                                /* No value required, check if it is enabled */
                                if (item->str_value != NULL)
                                        return (true);
                                else
                                        return (false);
                        }
                }
        }

        /* Not in list */
        return (false);
}

const char*
get_configuration_value(const char *identifier)
{
        /* If isConfigurationFlagEnabled() has been called before,
         * we'll try to use the item found there first */
        struct config_item_t *item = NULL;
        char *str_value = NULL;

        if (identifier == NULL)
                return (NULL);

        if (last_checked_item != NULL) {
                if (last_checked_item->str_value == NULL)
                        /* This really shouldn't happen */
                        errlogx(EX_DATAERR, "Internal data corruption"); /* exits */

                if (strcmp(last_checked_item->identifier, identifier) == 0) {
                        str_value = last_checked_item->str_value;
                        last_checked_item = NULL; /* Reset */
                        return (str_value);
                } else {
                        /* last_checked_item led to a wrong item ... let's clear it */
                        last_checked_item = NULL;
                }
        }
        /* Else we need to traverse the list */
        SLIST_FOREACH(item, &config_head, next_item) {
                if (strcmp(identifier, item->identifier) == 0)
                        return (item->str_value);
        }
        /* Not found */
        return (NULL);
}

int
add_auth_entry(char *user, char *domain, char *password)
{
        struct authuser *auth_item;

        if (user == NULL || domain == NULL || password == NULL)
                return (EX_CONFIG);

        auth_item = malloc(sizeof(struct authuser));
        if (auth_item == NULL)
                return (EX_OSERR);

        auth_item->login = user;
        auth_item->host = domain;
        auth_item->password = password;

        SLIST_INSERT_HEAD(&authusers, auth_item, next);
        return (0);
}

#ifdef DEBUG_CONF
static void
print_configuration_settings(void)
{
        struct config_item_t *item;

        SLIST_FOREACH(item, &config_head, next_item) {
                printf("ID: %s\tValue: %s\n", item->identifier, item->str_value);
                printf("ID: %s\tValue: %s\n\n", item->identifier,
                                is_configuration_setting_enabled(item->identifier) ?
                                                "true" : "false");
        }
}
#endif

#ifdef DEBUG_CONF
static void
print_auth_items(void)
{
        struct authuser *item;

        SLIST_FOREACH(item, &authusers, next) {
                printf("User: '%s'\tHost: '%s'\tPassword: '%s'\n", item->login, item->host,
                                item->password);
        }
}
#endif

struct auth_details_t*
get_auth_details_for_host(const char *host)
{
        struct authuser *item;
        struct auth_details_t *user_details;

        if (host == NULL)
                return (NULL);

        SLIST_FOREACH(item, &authusers, next) {
                if (strcmp(item->host, host) == 0) {
                        user_details = malloc(sizeof(struct auth_details_t));
                        if (user_details == NULL)
                                return (NULL);

                        user_details->login = strdup(item->login);
                        user_details->password = strdup(item->password);
                        if (user_details->login == NULL || user_details->password == NULL) {
                                free(user_details->login);
                                free(user_details->password);
                                free(user_details);
                                return (NULL);
                        }

                        return (user_details);
                }
        }

        /* Not found */
        return (NULL);
}

#ifdef DEBUG_CONF
static void
print_masquerade_settings(void)
{
        struct masquerade_config_t *masquerade = NULL;

        if (is_configuration_setting_enabled(CONF_MASQUERADE)) {
                masquerade = extract_masquerade_settings(
                                get_configuration_value(CONF_MASQUERADE));
                if (masquerade != NULL)
                        printf("Masquerade Host: '%s'\tUser: '%s'\n", masquerade->host,
                                        masquerade->user);
        }
        free_masquerade_settings(masquerade);
}
#endif

/* Check function for the MAILNAME setting
 * this function only returns non-zero in the case of a probable data corruption
 * All other checks can only lead to warning messages,
 * as an invalid MAILNAME configuration does not prevent local mails from working properly
 */
static int
check_mailname_configuration(const char *identifier, const char *value)
{
        FILE *mailname;
        char buffer[HOST_NAME_MAX +1] = { 0 }; /* Maximum hostname size + 1 '\0' */
        size_t counter, length;

        if(identifier == NULL || value == NULL)
                return (1);

        mailname = fopen(value, "r");
        if(mailname == NULL) {
                log_warning("Error opening %s: %s", value, strerror(errno));
                return (0);
        }
        fgets(buffer, sizeof(buffer), mailname);

        length = strlen(buffer);
        for(counter = 0; counter < length; counter++) {
                if(!isalnum(buffer[counter]) && buffer[counter] != '-' && buffer[counter] != '.') {

                        if(buffer[counter] == '\n')
                                buffer[counter] = '\0';
                        else
                                log_warning("Warning: Invalid character '%c' in hostname: '%s'", buffer[counter], buffer);

                        break; /* No matter if the char is invalid or just a newline:
                                * We're done here */
                }
        }

#ifdef DEBUG_CONF
        printf("Checked file '%s' with '%s' as contents.\n", value, buffer);
        printf("Mailname configuration ended.\n");
#endif

        return (0);
}
