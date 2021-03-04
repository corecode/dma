%{

#include <string.h>
#include "auth_parse.h"

%}

%option yylineno
%option noinput nounput
%option prefix="auth_"
%option noyywrap
%x pass_t
%x host_t


USER	   		[^[:space:][:cntrl:]\|:]+
HOSTNAME		[[:alnum:]][[:alnum:]\.\-]*[[:alnum:]]+
PASSWORD		[^[:cntrl:]]+$
BLANKS			[[:blank:]]+

%%

{USER}									{ auth_lval.str_type = strdup(yytext); return T_USERNAME; }
\|										{ BEGIN(host_t); return T_PIPE; }
<host_t>{HOSTNAME}						{ BEGIN(INITIAL); auth_lval.str_type = strdup(yytext); return T_HOSTNAME; }
:										{ BEGIN(pass_t); return T_COLON; }
<pass_t>{PASSWORD}						{ auth_lval.str_type = strdup(yytext); BEGIN(INITIAL); return T_PASSWORD; }



^(\r?\n?[[:blank:]]*(#.*)?)+			;  /*  ignore lines that are empty from the beginning
													*(and optionally comments without anything
													* but spaces before) */
													
<*>{BLANKS}								; /* Blanks are silently ignored. Passwords
										   * may contain spaces though */

\r?\n									;

<*>.									{ return T_ERROR; }

%%

