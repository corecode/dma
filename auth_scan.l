%{

#include <string.h>
#include "auth_parse.h"

%}

%option yylineno
%option noinput nounput
%option prefix="auth_"
%option noyywrap
%x pass_t

USER	   		[^[:space:][:cntrl:]\|:\.]+
HOSTNAME		[[:alnum:]][[:alnum:]\.\-]*[[:alnum:]]+
PASSWORD		[^[:cntrl:]]+$
BLANKS			[[:blank:]]+

%%

{USER}									{ auth_lval.str_type = strdup(yytext); return T_USERNAME; }
{HOSTNAME}								{ auth_lval.str_type = strdup(yytext); return T_HOSTNAME; }
\|										{ return T_PIPE; }
:										{ BEGIN(pass_t); return T_COLON; }
<pass_t>{PASSWORD}						{ auth_lval.str_type = strdup(yytext); BEGIN(INITIAL); return T_PASSWORD; }



{BLANKS}								; /* Blanks are silently ignored when not 
										   * parsing the password as passwords
										   * may contain spaces as well */

^(\r?\n?[[:blank:]]*(#.*)?)+			;  /*  ignore lines that are empty from the beginning
													*(and optionally comments without anything
													* but spaces before) */
\r?\n									;

<*>.									{ return T_ERROR; }

%%