%{
#include <stdio.h>
#include "dma.h"

int conf_lex(void);
extern int conf_lineno;
int conf_error(const char *);

int conf_error(const char *s)
{
        extern char *conf_text;
	
        fprintf(stderr, "error %s at symbol: \"%s\" on line %d\n", s, conf_text, conf_lineno);
	
        return 0;
}
%}

%union
{
        char *str_type;
}

/* declare tokens */
%token <str_type> T_WORD
%token T_BLANK
%token T_NEWLINE

%%

settings: 
        /* empty */
        | settings setting              /* Main rule */
        | settings empty_statement
        ;

setting: T_WORD newline
        {
                if(try_to_set_configuration_setting($1, NULL) != 0) {
                        fprintf(stderr, "Line %d: '%s' invalid identifier or missing value\n",conf_lineno, $1);
                        free($1);
                        YYABORT;
                } else {
                        free($1); /* Free the identifier */
                }
        }
        | T_WORD blanks T_WORD newline
        {
                if(try_to_set_configuration_setting($1, $3) != 0) {
                        fprintf(stderr, "Line %d: '%s' invalid identifier or value '%s'\n",conf_lineno,$1, $3);
                        free($1);
                        free($3);
                        YYABORT;
                } else {
			free($1); /* Free the identifier */
                }
        }
        ;

blanks: T_BLANK
        | blanks T_BLANK
        ;

newline: T_NEWLINE
        | blanks T_NEWLINE
        ;

empty_statement: T_BLANK
        | T_NEWLINE
        ;

%%

