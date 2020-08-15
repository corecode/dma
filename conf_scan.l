%{

#include <string.h>
#include "conf_parse.h"

%}

%option yylineno
%option noinput nounput
%option prefix="conf_"
%option noyywrap

WORD   			[^[:space:][:cntrl:]#]+
BLANKS			[[:blank:]]+
%%

{WORD}							{ conf_lval.str_type = strdup(yytext); return T_WORD; }


(#.*)+$							/*	ignore comments till the end of a line
									we need to separately catch a new line in this case! */
									
{BLANKS}						return T_BLANK;

\\\r?\n							/* Ignore the newline if it's immediately preceeded by a backslash */
									

^(\r?\n?[[:blank:]]*(#.*)?)+	return T_NEWLINE;  /*  ignore lines that are empty from the beginning
													*(and optionally comments without anything
													* but spaces before) */
\r?\n							return T_NEWLINE;
.								;

%%