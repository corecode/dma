%{

#include <string.h>
#include "conf_parse.h"

%}

%option yylineno
%option noinput nounput
%option prefix="conf_"
%option noyywrap

WORD	                [^[:space:][:cntrl:]#]+
BLANKS                  [[:blank:]]+
%%

{WORD}                  { conf_lval.str_type = strdup(yytext); return T_WORD; }


(#.*)+$			return T_NEWLINE; /*	ignore comments till the end of a line */
									
{BLANKS}		return T_BLANK;

\\\r?\n			/* Ignore the newline if it's immediately preceeded by a backslash */
									


\r?\n			return T_NEWLINE;
.			;

%%

