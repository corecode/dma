%{
#include <stdio.h>
#include "dma.h"

int auth_lex(void);
extern int auth_lineno;
int auth_error(const char *);

int auth_error(const char *s)
{
        extern char *auth_text;
        
        fprintf(stderr, "error parsing %s at symbol: \"%s\" on line %d\n", s, auth_text, auth_lineno);
        
        return 0;
}
%}

%union
{
	char *str_type;
}

/* declare tokens */
%token <str_type> T_USERNAME
%token <str_type> T_HOSTNAME
%token <str_type> T_PASSWORD
%token T_PIPE
%token T_COLON
%token T_ERROR

%type <str_type> user
%type <str_type> host
%type <str_type> password

%%

auth_file: /* empty */
        | auth_file auth_setting
	
auth_setting: user T_PIPE host T_COLON password
        {
                if(add_auth_entry($1, $3, $5) != 0) {
                        fprintf(stderr, "Error adding authentication information to list.\n");
                        free($1);
                        free($3);
                        free($5);
                        YYABORT;
                }
        }

user:           T_USERNAME
host:           T_HOSTNAME
password:       T_PASSWORD

%%

