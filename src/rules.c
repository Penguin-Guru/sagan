/*
** Copyright (C) 2009-2019 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2019 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* rules.c
 *
 * Loads and parses the rule files into memory
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <pcre.h>

#include "version.h"

#include "sagan.h"
#include "sagan-defs.h"

#include "flexbit.h"
#include "flexbit-mmap.h"
#include "lockfile.h"
#include "classifications.h"
#include "rules.h"
#include "sagan-config.h"
#include "parsers/parsers.h"

#ifdef WITH_BLUEDOT
#include "processors/bluedot.h"
#endif

struct _SaganCounters *counters;
struct _SaganDebug *debug;
struct _SaganConfig *config;

#ifdef WITH_BLUEDOT

struct _Sagan_Bluedot_Cat_List *SaganBluedotCatList;

char *bluedot_time = NULL;
char *bluedot_type = NULL;

uint64_t bluedot_time_u32 = 0;

#endif

#ifdef HAVE_LIBLOGNORM
#include "liblognormalize.h"
struct liblognorm_struct *liblognormstruct;
struct liblognorm_toload_struct *liblognormtoloadstruct;
int liblognorm_count;
#endif

/* For pre-8.20 PCRE compatibility */
#ifndef PCRE_STUDY_JIT_COMPILE
#define PCRE_STUDY_JIT_COMPILE 0
#endif

struct _Class_Struct *classstruct = NULL;
struct _Sagan_Ruleset_Track *Ruleset_Track = NULL;

struct RuleHead *RuleHead = { 0 };
struct RuleBody *RuleBody = { 0 };

void Load_Rules( const char *ruleset ) {	// Processes a rulefile.
	FILE *rulesfile;
	char ruleset_fullname[MAXPATH];
	char rulebuf[RULEBUF];
	char LastLine[RULEBUF] = { 0 };	// Not sure if assignment is useful.
	int nest=0;
	int FileLineCount=0;
	char RuleSource[MAXPATH + 4];	// Should allow for at least three digit line counts.
	int i;
	//int RuleLineCount=0;
	//int RulesCollected=0;
	//Sagan_Log(NORMAL, "Still here: UNesting");

	/* Store rule set names/path in memory for later usage dynamic loading, etc */

	strlcpy(ruleset_fullname, ruleset, sizeof(ruleset_fullname));	// Not sure if/why this intermediary is necessary.
	if (( rulesfile = fopen(ruleset_fullname, "r" )) == NULL ) Sagan_Log(ERROR, "[%s, line %d] Cannot open rule file ( \"%s\" - %s)", __FILE__, __LINE__, ruleset_fullname, strerror(errno));

	Ruleset_Track = (_Sagan_Ruleset_Track *) realloc(Ruleset_Track, (counters->ruleset_track_count+1) * sizeof(_Sagan_Ruleset_Track));
	if ( Ruleset_Track == NULL ) Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _Sagan_Ruleset_Track. Abort!", __FILE__, __LINE__);

	memset(&Ruleset_Track[counters->ruleset_track_count], 0, sizeof(struct _Sagan_Ruleset_Track));
	memcpy(Ruleset_Track[counters->ruleset_track_count].ruleset, ruleset_fullname, sizeof(Ruleset_Track[counters->ruleset_track_count].ruleset));

	__atomic_add_fetch(&counters->ruleset_track_count, 1, __ATOMIC_SEQ_CST);	// Tracks count of rule files.

	Sagan_Log(NORMAL, "Loading %s rule file.", ruleset_fullname);

	while ( fgets(rulebuf, sizeof(rulebuf), rulesfile) != NULL ) {
		FileLineCount++;
		if ( strchr(rulebuf, '#') - rulebuf <= strspn(rulebuf, "# \t\n\v\f\r") ) {	// Skip commented lines, ignoring white-space.
			//Sagan_Log(NORMAL, "Skipped line %d: \"%s\".", i, rulebuf);
			continue;
		}

		//strlcat(RuleSource, basename(ruleset_fullname), sizeof(RuleSource));
		strlcat(RuleSource, basename(ruleset_fullname), sizeof(RuleSource));
		snprintf(RuleSource + strlen(RuleSource), sizeof(RuleSource) - 1 - strlen(RuleSource), ":%d", FileLineCount);
		//Sagan_Log(NORMAL, "RuleSource = \"%s\"", RuleSource);

		Remove_Return(rulebuf);	// Could just cut off the end.
		//Sagan_Log(NORMAL, "Load_Rules: rulebuf = \"%s\"", rulebuf);

		//ParseLine(rulebuf, strlen(rulebuf), LastLine, sizeof(LastLine), &nest, &RuleSource);
		for (i=0; i<strlen(rulebuf); i++) {	// Rule is done.
			if ( rulebuf[i] == '(' ) nest = nest+1;	// nest++ does not work. Can argument be declared as *nest?
			else if ( rulebuf[i] == ')' ) nest = nest-1;

			if ( nest == 0 && rulebuf[i] == ';' ) {
				strlcat(LastLine, rulebuf, RULEBUF - strlen(LastLine) - (strlen(rulebuf) - i));	// Truncate after semicolon.
				//Sagan_Log(NORMAL, "Load_Rules: LastLine = \"%s\"", LastLine);
				ParseRule(LastLine, RuleSource);
				//memset(LastLine, '\0', LastLine_size);	// Reset.
				strlcpy(LastLine, rulebuf + i + 1, RULEBUF - (strlen(rulebuf) - i));	// Reset and resume parsing of same line.
			}
		}
		strlcat(LastLine, rulebuf, RULEBUF - strlen(LastLine));	// Rulebuf is sizeof(LastLine).

		RuleSource[0] = '\0';
	}
	fclose(rulesfile);
}

/*unsigned short ParseLine(char *rulebuf, int rulebuf_length, char *LastLine, int LastLine_size, int *nest, char *RuleSource) {	// Separate function because C doesn't seem to support "continue" from nested loops.
	unsigned int i;

	for (i=0; i<rulebuf_length; i++) {	// Rule is done. This probably fails if rule ends on same line as another rule starts.
		//Sagan_Log(NORMAL, "rulebuf[%d] = \'%c\'.", i, rulebuf[i]);
		//if ( rulebuf[i] == '(' ) Sagan_Log(NORMAL, "\t\"%c\" == '('", rulebuf[i]);
		if ( rulebuf[i] == '(' ) *nest = *nest+1;	// *nest++ does not work. Can argument be declared as **nest?
		else if ( rulebuf[i] == ')' ) *nest = *nest-1;
		//Sagan_Log(NORMAL, "processing %c (nest = %d)", rulebuf[i], nest);

		if ( *nest == 0 && rulebuf[i] == ';' ) {
			//RulesCollected++;
			//Sagan_Log(NORMAL, "RulesCollected = %d ", RulesCollected);
			//RuleLineCount = 0;
			strlcat(LastLine, rulebuf, LastLine_size);
			//Sagan_Log(NORMAL, "UNested: %s ", LastLine);
			//Sagan_Log(NORMAL, "ParseLine = 0 ; LastLine=\"%s\" ; nest = %d", LastLine, *nest);
			//ParseRule(LastLine, LastLine_size);
			//ParseRule(rulebuf, RuleSource);
			ParseRule(LastLine, RuleSource);
			memset(LastLine, '\0', LastLine_size);	// Reset.
			// Support for multiple rules per line would be added here.
			return 0;
		}
	}
	strlcat(LastLine, rulebuf, LastLine_size);
	//Sagan_Log(NORMAL, "ParseLine = 1 ; rulebuf = \"%s\" ; LastLine=\"%s\" ; nest = %d", rulebuf, LastLine, *nest);
	return 1;
}*/

void ParseRule(char *rulebuf, char *RuleSource) {
	char *begin;
	char *end;
	//int ruleset_track_id = 0;

	//Sagan_Log(NORMAL, "ParseRule: rulebuf = \"%s\"", rulebuf);

	/* Allocate memory for rules: */
	/* Could reduce memory usage based on actual usage (i.e. not max addresses)? */
	//RuleHead = realloc(RuleHead, (counters->rulecount+1) * sizeof(RuleHead));
	RuleHead = realloc(RuleHead, (counters->rulecount+1) * sizeof(struct RuleHead));	// Confirm whether to use "struct" or not.
	if ( RuleHead == NULL ) Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for RuleHead. Abort!", __FILE__, __LINE__);
	RuleBody = realloc(RuleBody, (counters->rulecount+1) * sizeof(struct RuleBody));	// Confirm whether to use "struct" or not.
	if ( RuleBody == NULL ) Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for RuleBody. Abort!", __FILE__, __LINE__);

	//ruleset_track_id = counters->ruleset_track_count;	// I'm not sure why this is necessary.
	//RuleHead[counters->rulecount].ruleset_id = ruleset_track_id;	// Why not just use the rule's (unique) sid?
	RuleHead[counters->rulecount].ruleset_id = counters->ruleset_track_count;	// Omitted intermediary "ruleset_track_id". This could probably be eliminated entirely.


	begin = strchr(rulebuf, '(');
	end = strrchr(rulebuf, ')');

	ParseRuleHead(rulebuf, begin - rulebuf);	// Using begin as length should drop rule body.
	//PrintRuleHeadDebug();
	//
	ParseRuleBody(begin + 1, (end - 1) - (begin + 1), RuleSource);	// This will not process content after last ')'. Assuming desirable.
	//PrintRuleBodyDebug();

	//ParseRuleTail(end, strlen(rulebuf) - end);	// Could contain meta-data like sid, rev, etc...

	__atomic_add_fetch(&counters->rulecount, 1,  __ATOMIC_SEQ_CST);	// Increment rulecount.
}

void ParseRuleHead(char *rulebuf, int headbuf_length) {
	//char headbuf[headbuf_length];
	long headbuf[headbuf_length];
	char *Word;
	char *WordNav;	// Not sure if necessary.
	//char WordExp[1024];	// Is this a good length?
	bool NegateNext = false;
	int WordNumber = 0;
	unsigned short i;
	unsigned short Complexity = 0;

	//Sagan_Log(NORMAL, "headbuf_length = %d", headbuf_length);
	strlcpy(headbuf, rulebuf, headbuf_length);

	WordNumber=0;
	//Word = strtok(headbuf, " \t\n\v\f\r");
	Word = strtok_r(headbuf, " \t\n\v\f\r", &WordNav);
	while (Word) {
		//Sagan_Log(NORMAL, "ParseRuleHead: Word = \"%s\"", Word);

		/* Parse free-word negation: */
		if ( !strcmp(Word, "!") || !strcasecmp(Word, "not") ) {
			// Set variable to negate next word.
			NegateNext = true;
			Word = strtok_r(NULL, " \t\n\v\f\r", &WordNav);	// Get next Word.
			continue;
		} else if (NegateNext == true) {
			/* This method probably won't work due to overwriting next Word. */
			//memmove(Word + 1, Word, strlen(Word) + 1);
			//Word[1] = '!';
			NegateNext = false;
		}

		WordNumber++;	// Not incremented for negation keywords.
		//Sagan_Log(NORMAL, "Word %d = \"%s\".", WordNumber, Word);

		if (WordNumber == 1) {
			/* Action type. */
			if (!strcasecmp(Word, "alert")) RuleHead[counters->rulecount].action = 1;
			else if (!strcasecmp(Word, "drop")) RuleHead[counters->rulecount].action = 2;
			else {
				Sagan_Log(WARN, "Rule ignored due to unknown action type: \"%s\" ", Word);
				return;
			}
		} else if (WordNumber == 2) {
			/* Action protocol. */
			if (!strcasecmp(Word, "any")) RuleHead[counters->rulecount].ip_proto = 0;
			else if (!strcasecmp(Word, "ip")) RuleHead[counters->rulecount].ip_proto = 0;
			else if (!strcasecmp(Word, "tcp")) RuleHead[counters->rulecount].ip_proto = 6;
			else if (!strcasecmp(Word, "udp")) RuleHead[counters->rulecount].ip_proto = 17;
			else if (!strcasecmp(Word, "syslog")) RuleHead[counters->rulecount].ip_proto = config->default_proto;	// This should probably be fixed.
			else if (!strcasecmp(Word, "unknown")) RuleHead[counters->rulecount].ip_proto = 255;
			else {
				Sagan_Log(WARN, "Rule ignored due to unknown action protocol: \"%s\" ", Word);
				return;
			}
		} else if (WordNumber == 3) ParseTargetAddress(Word, 0);
		else if (WordNumber == 4) ParseTargetPort(Word, 0);
		else if (WordNumber == 5) ParseDirection(Word);
		else if (WordNumber == 6) ParseTargetAddress(Word, 1);
		else if (WordNumber == 7) ParseTargetPort(Word, 1);


		//Word = strtok(NULL, " \t\n\v\f\r");	// Get next Word.
		Word = strtok_r(NULL, " \t\n\v\f\r", &WordNav);	// Get next Word.
	}	// End Word loop.

	/* Deactivate rules with unusable targeting: *
	RuleHead[counters->rulecount].is_active = true;
	for (i=0; i<2; i++) {
		if (! (RuleHead[counters->rulecount].target[i].any_address == true || RuleHead[counters->rulecount].target[i].address_count > 0)) {
			RuleHead[counters->rulecount].is_active = false;
			break;
		}
		if (! (RuleHead[counters->rulecount].target[i].any_port == true || RuleHead[counters->rulecount].target[i].port_count > 0)) {
			RuleHead[counters->rulecount].is_active = false;
			break;
		}
	}*/

	/* Fast-track simpler rules: */
	if (RuleHead[counters->rulecount].ip_proto > 0) Complexity++;
	for (i=0; i<2; i++) {
		if (RuleHead[counters->rulecount].target[i].any_address == false) Complexity++;
		if (RuleHead[counters->rulecount].target[i].any_port == false) Complexity++;
	}
	if (Complexity < 5) RuleHead[counters->rulecount].AllAny = true;
	else RuleHead[counters->rulecount].AllAny = false;

	//PrintConfigHeadDebug();
}

bool ParseTargetAddress(char *Word, int TargetNumber) {
	char WordExp[1024];	// Is this a good length?
	char *CommaProd;
	char *CommaNav;
	char NetClosure[MAX_CHECK_FLOWS * 21] = { 0 };	// Not sure this needs to be assigned here.
	char NetNots[64];
	int i;
	int CP_count=0; /* Need for flow_direction, must reset every rule, not every group */

	/* Expand config variables: */
	Var_To_Value(Word, WordExp, sizeof(WordExp));
	Remove_Spaces(WordExp);

	/* Unpack group syntax: */
	Strip_Chars2(WordExp, "][", NetClosure);	// No handling is implemented, just drop the brackets.

	/* Supercede grouping and negation: */
	if (!strcasecmp(WordExp, "any")) {	// Specifying "any" in group syntax does not make sense, so it should not be supported.
		RuleHead[counters->rulecount].target[TargetNumber].any_address = true;
		return true;
	}

	/* Explicit address: */

	for (CommaProd = strtok_r(NetClosure, ",", &CommaNav); CommaProd; CommaProd = strtok_r(NULL, ",", &CommaNav)) {

		/* Check for prepended, symbolic negation: */
		if (Drop_Not(CommaProd)) RuleHead[counters->rulecount].target[TargetNumber].address[CP_count].is_not = true;
		else RuleHead[counters->rulecount].target[TargetNumber].address[CP_count].is_not = false;

		/* Keyword checks: */
		if (!strcasecmp(CommaProd, "unknown")) {
			RuleHead[counters->rulecount].target[TargetNumber].address[CP_count].keyword = 2;
			//CP_count++;	// Call function to increment and check running count for address and port.
			if (ExceedFlows(&CP_count, "addresses")) break;
			else continue;
		}

		/* Not a keyword: */

		RuleHead[counters->rulecount].target[TargetNumber].address[CP_count].keyword = 0;

		//if (!Is_IP_Range(CommaProd)) Sagan_Log(WARN,"[%s, line %d] Value is not a valid IPv4/IPv6 '%s'", __FILE__, __LINE__, CommaProd);	// This strips CIDR suffix.

		Netaddr_To_Range(CommaProd, (unsigned char *)&RuleHead[counters->rulecount].target[TargetNumber].address[CP_count].ipbits);	// This will also write over maskbits.

		if (ExceedFlows(&CP_count, "addresses")) break;
	}	// End comma iteration.
	RuleHead[counters->rulecount].target[TargetNumber].address_count = RuleHead[counters->rulecount].target[TargetNumber].address_count + CP_count;
}

bool ExceedFlows(int *TheCount, char Name[10]) {	// Expected "Name" values: "addresses", "ports".
	if (*TheCount + 1 > MAX_CHECK_FLOWS) {
		Sagan_Log(WARN,"[%s, line %d] You have exceeded the max number of %s (%d). Target scope will be truncated.", __FILE__, __LINE__, Name, MAX_CHECK_FLOWS);
		return true;
	} else {
		*TheCount = *TheCount + 1;
		return false;
	}
}

bool ParseTargetPort(char *Word, int TargetNumber) {
	char WordExp[1024];	// Is this a good length?
	char *CommaProd;
	char *CommaNav;
	char *RangeNav;
	char NetNots[64];
	int CP_count = 0;

	/* Expand config variables: */
	Var_To_Value(Word, WordExp, sizeof(WordExp));
	Remove_Spaces(WordExp);

	/* Supercede grouping and negation: */
	if (!strcasecmp(WordExp, "any")) {	// Specifying "any" in group syntax does not make sense, so it should not be supported.
		RuleHead[counters->rulecount].target[TargetNumber].any_port = true;
		return true;
	}

	/* Explicit port: */

	//RuleHead[counters->rulecount].target[TargetNumber].keyword_port = 0;

	for (CommaProd = strtok_r(WordExp, ",", &CommaNav); CommaProd != NULL; CommaProd = strtok_r(NULL, ",", &CommaNav)) {

		/* Check for prepended, symbolic negation: */
		//if (Strip_Chars2(CommaProd, "not!", NetNots)) RuleHead[counters->rulecount].target[TargetNumber].port[CP_count].is_not = true;
		//else RuleHead[counters->rulecount].target[TargetNumber].port[CP_count].is_not = false;
		if (Drop_Not(CommaProd)) RuleHead[counters->rulecount].target[TargetNumber].port[CP_count].is_not = true;
		else RuleHead[counters->rulecount].target[TargetNumber].port[CP_count].is_not = false;

		/* Keyword checks: */
		if (!strcasecmp(CommaProd, "unknown")) {
			RuleHead[counters->rulecount].target[TargetNumber].port[CP_count].keyword = 2;
			//CP_count++;	// Call function to increment and check running count for address and port.
			if (ExceedFlows(&CP_count, "ports")) break;
			else continue;
		}

		/* Not a keyword: */

		//RuleHead[counters->rulecount].target[TargetNumber].port[CP_count].keyword = 0;

		if (strchr(CommaProd, ':')) {	// Colon denotes range.
		//if (Delim = strchr(CommaProd, ':')) {	// Colon denotes range.
			//Delim = strchr(CommaProd, ':');
			//RuleHead[counters->rulecount].target[TargetNumber].port[CP_count].is_range = true;
			RuleHead[counters->rulecount].target[TargetNumber].port[CP_count].low = atoi(strtok_r(CommaProd, ":", &RangeNav));
			RuleHead[counters->rulecount].target[TargetNumber].port[CP_count].high = atoi(strtok_r(NULL, ":", &RangeNav));
			//strlcpy(RuleHead[counters->rulecount].target[TargetNumber].port[CP_count].low, CommaProd, Delim - CommaProd);
			//strlcpy(RuleHead[counters->rulecount].target[TargetNumber].port[CP_count].high, Delim, strlen(CommaProd) - (Delim - CommaProd));
		} else {	// Not a range.
			//RuleHead[counters->rulecount].target[TargetNumber].port[CP_count].is_range = false;
			RuleHead[counters->rulecount].target[TargetNumber].port[CP_count].low = atoi(CommaProd);
			RuleHead[counters->rulecount].target[TargetNumber].port[CP_count].high = atoi(CommaProd);
		}

		// Should probably include some more sophisticated validity checks here. Return false if not comprehensible.

		if (ExceedFlows(&CP_count, "ports")) break;
	}	// End comma iteration.
	RuleHead[counters->rulecount].target[TargetNumber].port_count = RuleHead[counters->rulecount].target[TargetNumber].port_count + CP_count;

	return true;
}

bool ParseDirection(char *Word) {
	if (!strcmp(Word, "->")) {
		RuleHead[counters->rulecount].direction = 1;
		return true;
	}
	if (!strcasecmp(Word, "any")) {
		RuleHead[counters->rulecount].direction = 0;
		return true;
	}
	if (!strcmp(Word, "<->")) {
		RuleHead[counters->rulecount].direction = 0;
		return true;
	}
	if (!strcmp(Word, "<>")) {
		RuleHead[counters->rulecount].direction = 0;
		return true;
	}
	if (!strcmp(Word, "<-")) {
		RuleHead[counters->rulecount].direction = 2;
		return true;
	}

	return false;
}

void PrintRuleHeadDebug() {
	Sagan_Log(NORMAL, "action: %d", RuleHead[counters->rulecount].action);
	Sagan_Log(NORMAL, "ip_proto: %d", RuleHead[counters->rulecount].ip_proto);

	PrintRuleTargetDebug(0);

	Sagan_Log(NORMAL, "\ndirection: %d", RuleHead[counters->rulecount].direction);

	PrintRuleTargetDebug(1);

	Sagan_Log(NORMAL, "\nAllAny: %s", RuleHead[counters->rulecount].AllAny ? "true" : "false");
}

void PrintRuleTargetDebug(int TargetNumber) {
	char tmp[INET_ADDRSTRLEN];
	int i;
	
	Sagan_Log(NORMAL, "\naddress_count: %d", RuleHead[counters->rulecount].target[TargetNumber].address_count);
	if (RuleHead[counters->rulecount].target[TargetNumber].any_address == true) Sagan_Log(NORMAL, "\t\tANY");
	else {
		for (i=0; i<RuleHead[counters->rulecount].target[TargetNumber].address_count; i++) {
			Sagan_Log(NORMAL, "\t%d:", i);
			Sagan_Log(NORMAL, "\t\tis_not: %s ", RuleHead[counters->rulecount].target[TargetNumber].address[i].is_not ? "true" : "false");
			Sagan_Log(NORMAL, "\t\tkeyword: %hu ", RuleHead[counters->rulecount].target[TargetNumber].address[i].keyword);
			inet_ntop(AF_INET, &RuleHead[counters->rulecount].target[TargetNumber].address[i].ipbits, tmp, INET_ADDRSTRLEN);
			Sagan_Log(NORMAL, "\t\tipbits: %s ", tmp);
			inet_ntop(AF_INET, &RuleHead[counters->rulecount].target[TargetNumber].address[i].maskbits, tmp, INET_ADDRSTRLEN);
			Sagan_Log(NORMAL, "\t\tmaskbits: %s ", tmp);
		}
	}

	Sagan_Log(NORMAL, "\nport_count: %d", RuleHead[counters->rulecount].target[TargetNumber].port_count);
	if (RuleHead[counters->rulecount].target[TargetNumber].any_port == true) Sagan_Log(NORMAL, "\t\tANY");
	else {
		for (i=0; i<RuleHead[counters->rulecount].target[TargetNumber].port_count; i++) {
			Sagan_Log(NORMAL, "\t%d:", i);
			Sagan_Log(NORMAL, "\t\tis_not: %s ", RuleHead[counters->rulecount].target[TargetNumber].port[i].is_not ? "true" : "false");
			Sagan_Log(NORMAL, "\t\tkeyword: %hu ", RuleHead[counters->rulecount].target[TargetNumber].port[i].keyword);
			Sagan_Log(NORMAL, "\t\tlow: %d ", RuleHead[counters->rulecount].target[TargetNumber].port[i].low);
			Sagan_Log(NORMAL, "\t\thigh: %d ", RuleHead[counters->rulecount].target[TargetNumber].port[i].high);
		}
	}
}

//void ParseRuleBody(char *rulebuf, int bb_begin, int bb_end) {
void ParseRuleBody(char *bodybuf, int bb_length, char *RuleSource) {
	char *Declaration;
	char *DeclarationNav;
	char *Delim;
	char Key[30];	// This length should probably be defined elsewhere.
	char Value[RULEBUF - 30];	// sizeof(Key).
	//int tmp;

	//Sagan_Log(NORMAL, "bodybuf = \"%s\" ", bodybuf);

	Declaration = strtok_r(bodybuf, ";", &DeclarationNav);
	while (Declaration != NULL && Declaration - bodybuf < bb_length) {
		//Sagan_Log(NORMAL, "Declaration = \"%s\"", Declaration);
		Delim = strchr(Declaration, ':');
		//Sagan_Log(NORMAL, "Delim = \"%s\"", Delim);
		//tmp = strspn(Declaration, " \t");	// Count indentation to skip.
		//if (Delim - Declaration < sizeof(Key)) strlcpy(Key, Declaration + tmp, Delim - Declaration - tmp);	// Delim replaced by null.
		if (Delim - Declaration < sizeof(Key)) strlcpy(Key, Declaration + strspn(Declaration, " \t"), Delim - Declaration);	// Delim replaced by null.
		//else Sagan_Log(ERROR, "Bad Key: %d >= %d", Delim - Declaration, sizeof(Key));
		//Sagan_Log(NORMAL, "Key = \"%s\"", Key);

		//tmp = strspn(Delim+1, " \t");	// Count indentation to skip.
		if (DeclarationNav - Delim <= sizeof(Value)) strlcpy(Value, Delim + 1 + strspn(Delim+1, " \t"), DeclarationNav);	// Delim replaced by null.
		//else Sagan_Log(ERROR, "Bad Value: %d >= %d", DeclarationNav - Delim, sizeof(Value));
		//Sagan_Log(NORMAL, "Value = \"%s\"", Value);

		/* Hopefully this should be here: */
		/*if (Value == NULL) {
			Sagan_Log(WARN, "[%s, line %d] Null value for key, \"%s\", on line %d of %s. Skipping rule.", __FILE__, __LINE__, Key, linecount, ruleset_fullname);
			BadRule = true;
			break;
		}*/

		/* This list should be sorted by probability of use. Consider using switch/case with hashes. */
		/* Separate stanza at top for any essential keys. All functions should return false (or >0) on failure to allow for contitional breaks. */

//		if (!strcasecmp(Key, "after")) ParseRuleKey_After(&Value, RuleSource);
//		else if (!strcasecmp(Key, "alert_time")) ParseRuleKey_AlertTime(&Value, RuleSource);
//		else if (!strcasecmp(Key, "blacklist")) ParseRuleKey_Blacklist(&Value, RuleSource);
//		else if (!strcasecmp(Key, "bluedot")) ParseRuleKey_Bluedot(&Value, RuleSource);
//		else if (!strcasecmp(Key, "zeek-intel")) ParseRuleKey_ZeekIntel(&Value, RuleSource);
		if (!strcasecmp(Key, "classtype")) ParseRuleKey_Classtype(&Value, RuleSource);	// Would be if else.
		else if (!strcasecmp(Key, "content")) ParseRuleKey_Content(&Value, RuleSource);
//		else if (!strcasecmp(Key, "country_code")) ParseRuleKey_CountryCode(&Value, RuleSource);
//		else if (!strcasecmp(Key, "default_proto")) ParseRuleKey_DefaultProto(&Value, RuleSource);
//		else if (!strcasecmp(Key, "default_dst_port")) ParseRuleKey_DefaultDstPort(&Value, RuleSource);
//		else if (!strcasecmp(Key, "default_src_port")) ParseRuleKey_DefaultSrcPort(&Value, RuleSource);
//		else if (!strcasecmp(Key, "depth")) ParseRuleKey_Depth(&Value, RuleSource);
//		else if (!strcasecmp(Key, "distance")) ParseRuleKey_Distance(&Value, RuleSource);
//		else if (!strcasecmp(Key, "dynamic_load")) ParseRuleKey_DynamicLoad(&Value, RuleSource);
//		else if (!strcasecmp(Key, "email")) ParseRuleKey_Email(&Value, RuleSource);
//		else if (!strcasecmp(Key, "external")) ParseRuleKey_External(&Value, RuleSource);
//		else if (!strcasecmp(Key, "syslog_facility")) ParseRuleKey_SyslogFacility(&Value, RuleSource);
//		else if (!strcasecmp(Key, "flexbits")) ParseRuleKey_Flexbits(&Value, RuleSource);
//		else if (!strcasecmp(Key, "flexbits_pause")) ParseRuleKey_FlexbitsPause(&Value, RuleSource);
//		else if (!strcasecmp(Key, "fwsam")) ParseRuleKey_FwSam(&Value, RuleSource);
//		else if (!strcasecmp(Key, "syslog_level")) ParseRuleKey_SyslogLevel(&Value, RuleSource);
//		else if (!strcasecmp(Key, "meta_content")) ParseRuleKey_MetaContent(&Value, RuleSource);
//		else if (!strcasecmp(Key, "meta_depth")) ParseRuleKey_MetaDepth(&Value, RuleSource);
//		else if (!strcasecmp(Key, "meta_distance")) ParseRuleKey_MetaDistance(&Value, RuleSource);
//		else if (!strcasecmp(Key, "meta_offset")) ParseRuleKey_MetaOffset(&Value, RuleSource);
//		else if (!strcasecmp(Key, "meta_nocase")) ParseRuleKey_MetaNoCase(&Value, RuleSource);
//		else if (!strcasecmp(Key, "meta_within")) ParseRuleKey_MetaWithin(&Value, RuleSource);
		else if (!strcasecmp(Key, "msg")) ParseRuleKey_Msg(&Value, RuleSource);
//		else if (!strcasecmp(Key, "nocase")) ParseRuleKey_NoCase(&Value, RuleSource);
//		else if (!strcasecmp(Key, "normalize")) ParseRuleKey_Normalize(&Value, RuleSource);
//		else if (!strcasecmp(Key, "offset")) ParseRuleKey_Offset(&Value, RuleSource);
//		else if (!strcasecmp(Key, "parse_dst_ip")) ParseRuleKey_ParseDstIp(&Value, RuleSource);
		else if (!strcasecmp(Key, "parse_port")) ParseRuleKey_ParsePort(&Value, RuleSource);
		else if (!strcasecmp(Key, "parse_proto")) ParseRuleKey_ParseProto(&Value, RuleSource);
		else if (!strcasecmp(Key, "parse_proto_program")) ParseRuleKey_ParseProtoProgram(&Value, RuleSource);
//		else if (!strcasecmp(Key, "parse_hash")) ParseRuleKey_ParseHash(&Value, RuleSource);
//		else if (!strcasecmp(Key, "parse_src_ip")) ParseRuleKey_ParseSrcIp(&Value, RuleSource);
//		else if (!strcasecmp(Key, "pcre")) ParseRuleKey_Pcre(&Value, RuleSource);
//		else if (!strcasecmp(Key, "priority")) ParseRuleKey_Priority(&Value, RuleSource);
		else if (!strcasecmp(Key, "program")) ParseRuleKey_Program(&Value, RuleSource);
//		else if (!strcasecmp(Key, "reference")) ParseRuleKey_Reference(&Value, RuleSource);
		else if (!strcasecmp(Key, "rev")) ParseRuleKey_Rev(&Value, RuleSource);
		else if (!strcasecmp(Key, "sid")) ParseRuleKey_Sid(&Value, RuleSource);
//		else if (!strcasecmp(Key, "syslog_tag")) ParseRuleKey_SyslogTag(&Value, RuleSource);
//		else if (!strcasecmp(Key, "threshold")) ParseRuleKey_Threshold(&Value, RuleSource);
//		else if (!strcasecmp(Key, "within")) ParseRuleKey_Within(&Value, RuleSource);
//		else if (!strcasecmp(Key, "xbits")) ParseRuleKey_Xbits(&Value, RuleSource);
//		else if (!strcasecmp(Key, "xbits_pause")) ParseRuleKey_XbitsPause(&Value, RuleSource);
//		else if (!strcasecmp(Key, "xbits_upause")) ParseRuleKey_XbitsUpause(&Value, RuleSource);


		Declaration = strtok_r(NULL, ";", &DeclarationNav);	// Get next Declaration.
	}
}

bool ParseRuleKey_Classtype(char *Value, char *RuleSource) {
	bool found = false;
	int i;

	Remove_Spaces(Value);
	strlcpy(RuleBody[counters->rulecount].s_classtype, Value, sizeof(RuleBody[counters->rulecount].s_classtype));

	found = true;
	for(i=0; i<counters->classcount; i++) {
		if (!strcmp(classstruct[i].s_shortname, RuleBody[counters->rulecount].s_classtype)) {
			RuleBody[counters->rulecount].s_pri = classstruct[i].s_priority;
			found = true;
			break;
		}
	}

	if (found == false) {
		//Sagan_Log(WARN, "[%s, line %d] The classtype \"%s\" was not found on line %d in %s! Rule will be skipped. \n Are you attempting loading a rule set before loading the classification.config?", __FILE__, __LINE__, RuleBody[counters->rulecount].s_classtype, linecount, ruleset_fullname);
		Sagan_Log(WARN, "[%s, line %d] The classtype \"%s\" was not found-- rule will be skipped. RuleSource: %s", __FILE__, __LINE__, RuleBody[counters->rulecount].s_classtype, RuleSource);
		Sagan_Log(WARN, "Are you attempting to load a rule set before loading the classigication.config?");
		return false;
	} else return true;
}

bool ParseRuleKey_Content(char *Value, char *RuleSource) {
	char NetQuotes[RULEBUF] = { 0 };
	char Hexpanded[RULEBUF] = { 0 };
	//int content_count = atoi(RuleBody[counters->rulecount].content_count);
	int content_count = RuleBody[counters->rulecount].content_count;

	if (content_count > MAX_CONTENT) {
		Sagan_Log(WARN, "[%s, line %d] Exceeded maximum number of \"content\" fields (%d)-- skipping this one. See %s ", __FILE__, __LINE__, MAX_CONTENT, RuleSource);
		return true;
	}

	if ( Check_Content_Not(Value) == true ) RuleBody[counters->rulecount].content_not[content_count] = true;	// Symbolic negation.

	Between_Quotes(Value, NetQuotes, sizeof(NetQuotes));
	if (NetQuotes[0] == '\0') {	// Consider writing this into Between_Quotes for return value conditional.
		Sagan_Log(WARN, "[%s, line %d] Null \"content\" field (%d) within quotes. See: %s ", __FILE__, __LINE__, content_count, RuleSource);
		return false;
	}

	/* Convert HEX encoded data: */
	Content_Pipe2(NetQuotes, RuleSource, Hexpanded, sizeof(Hexpanded));	// Untested.
	//strlcpy(final_content, Hexpanded, sizeof(final_content));

	strlcpy(RuleBody[counters->rulecount].s_content[content_count], Hexpanded, sizeof(RuleBody[counters->rulecount].s_content[content_count]));
	//final_content[0] = '\0';
	content_count++;
	RuleBody[counters->rulecount].content_count = content_count;
	return true;
}

bool ParseRuleKey_Msg(char *Value, char *RuleSource) {
	char tmp[RULEBUF] = { 0 };

	//Sagan_Log(NORMAL, "ParseRuleKey_Msg: Value = \"%s\"", Value);
	Between_Quotes(Value, tmp, sizeof(tmp));
	if (tmp[0] == '\0') {
		Sagan_Log(WARN, "[%s, line %d] Null \"msg\" field within quotes. See: %s ", __FILE__, __LINE__, RuleSource);
		return false;
	}
	strlcpy(RuleBody[counters->rulecount].s_msg, tmp, sizeof(RuleBody[counters->rulecount].s_msg));
	return true;
}

bool ParseRuleKey_ParsePort(char *Value, char *RuleSource) {
	if (Value) Sagan_Log(NORMAL, "Rule key \"parse_port\" does not accept any value.");
	if ((RuleBody[counters->rulecount].s_find_port = true)) return true;
	else return false;
}

bool ParseRuleKey_ParseProto(char *Value, char *RuleSource) {
	if (Value) Sagan_Log(NORMAL, "Rule key \"parse_proto\" does not accept any value.");
	if ((RuleBody[counters->rulecount].s_find_proto = true)) return true;
	else return false;
}

bool ParseRuleKey_ParseProtoProgram(char *Value, char *RuleSource) {
	if (Value) Sagan_Log(NORMAL, "Rule key \"parse_proto_program\" does not accept any value.");
	if ((RuleBody[counters->rulecount].s_find_proto_program = true)) return true;
	else return false;
}

bool ParseRuleKey_Program(char *Value, char *RuleSource) {
	char tmp[CONFBUF] = { 0 };

	Var_To_Value(Value, tmp, sizeof(tmp));
	Remove_Spaces(tmp);
	if (tmp[0] == '\0') {
		Sagan_Log(WARN, "[%s, line %d] Null \"program\" field after expansion. See: %s ", __FILE__, __LINE__, RuleSource);
		return false;
	}
	strlcpy(RuleBody[counters->rulecount].s_program, tmp, sizeof(RuleBody[counters->rulecount].s_program));
	return true;
}

bool ParseRuleKey_Rev(char *Value, char *RuleSource) {
	Remove_Spaces(Value);	// Not sure if useful.
	RuleBody[counters->rulecount].s_rev = atol(Value);
	return true;
}

bool ParseRuleKey_Sid(char *Value, char *RuleSource) {
	Remove_Spaces(Value);	// Not sure if useful.
	RuleBody[counters->rulecount].s_sid = atol(Value);	// Consider using a finction capable of returning error status.
	return true;
}

void PrintRuleBodyDebug() {
	int i;
	int tmpi = 0;

	Sagan_Log(NORMAL, "s_msg = \"%s\"", RuleBody[counters->rulecount].s_msg);
	tmpi = RuleBody[counters->rulecount].content_count;
	for (i=0; i<tmpi; i++) {
		Sagan_Log(NORMAL, "content[%d] = \"%s\"", i, RuleBody[counters->rulecount].s_content[i]);
	}
	Sagan_Log(NORMAL, "s_classtype = \"%s\"", RuleBody[counters->rulecount].s_classtype);
	Sagan_Log(NORMAL, "s_pri = \"%d\"", RuleBody[counters->rulecount].s_pri);
	Sagan_Log(NORMAL, "s_program = \"%s\"", RuleBody[counters->rulecount].s_program);
	Sagan_Log(NORMAL, "s_sid = \"%d\"", RuleBody[counters->rulecount].s_sid);
	Sagan_Log(NORMAL, "s_rev = \"%d\"", RuleBody[counters->rulecount].s_rev);
}
