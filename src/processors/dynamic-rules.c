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

/* dynamic-load.c
 *
 * This loads rule sets dynamically based off 'dynamic' rules.  The idea is
 * for Sagan to detect logs it might not be monitoring and automatically
 * enable and/or warn the operator.
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <sys/time.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "rules.h"
#include "sagan-config.h"
#include "send-alert.h"

#include "processors/dynamic-rules.h"

struct _SaganConfig *config;
struct RuleBody *RuleBody;
struct _Rules_Loaded *rules_loaded;
struct _SaganCounters *counters;

bool reload_rules;

pthread_mutex_t SaganRulesLoadedMutex;
pthread_mutex_t CounterDynamicGenericMutex=PTHREAD_MUTEX_INITIALIZER;

int Sagan_Dynamic_Rules ( _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL, int rule_position, _Sagan_Processor_Info *processor_info_engine, char *ip_src, char *ip_dst )
{

    int i;

    struct timeval  tp;

    /* We don't want the array to be altered while we are working with it */

    pthread_mutex_lock(&SaganRulesLoadedMutex);
    reload_rules = 1;

    for (i=0; i<counters->rules_loaded_count; i++)
        {

            /* If the rule set is loaded (or in our array), nothing else needs to be done */

            if (!strcmp(RuleBody[rule_position].DynamicLoad.dynamic_ruleset, rules_loaded[i].ruleset))
                {

                    /* Rule was already loaded.  Release mutex and continue as normal */

                    pthread_mutex_unlock(&SaganRulesLoadedMutex);
                    return(0);
                }
        }

    /* Since rule was not loaded,  add it to our rule list */

    rules_loaded = (_Rules_Loaded *) realloc(rules_loaded, (counters->rules_loaded_count+1) * sizeof(_Rules_Loaded));

    if ( rules_loaded == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for rules_loaded. Abort!", __FILE__, __LINE__);
        }

    memset(&rules_loaded[counters->rules_loaded_count], 0, sizeof(_Rules_Loaded));

    strlcpy(rules_loaded[counters->rules_loaded_count].ruleset, RuleBody[rule_position].DynamicLoad.dynamic_ruleset, sizeof(rules_loaded[counters->rules_loaded_count].ruleset));

    __atomic_add_fetch(&counters->rules_loaded_count, 1, __ATOMIC_SEQ_CST);

    /* Done here,  release so others can process */

    reload_rules = 0;
    pthread_mutex_unlock(&SaganRulesLoadedMutex);

    /*****************************/
    /* Load rules, log and alert */
    /*****************************/

    if ( config->dynamic_load_type == 0 )
        {

            Sagan_Log(NORMAL, "Detected dynamic signature '%s'. Dynamically loading '%s'.", RuleBody[rule_position].s_msg, RuleBody[rule_position].DynamicLoad.dynamic_ruleset);

            gettimeofday(&tp, 0);

            /* Process the alert _before_ loading rule set! Otherwise, mem will mismatch */
            Send_Alert(SaganProcSyslog_LOCAL,
                       NULL,
                       processor_info_engine,
                       ip_src,
                       ip_dst,
                       "",
                       "",
                       config->default_proto,
                       RuleBody[rule_position].s_sid,
                       config->default_port,
                       config->default_port,
                       rule_position, tp, NULL, 0 );

            /* Lock rules so other threads don't try to use it while we alter/load new rules */

            pthread_mutex_lock(&SaganRulesLoadedMutex);
            reload_rules = 1;

            Load_Rules(RuleBody[rule_position].DynamicLoad.dynamic_ruleset);

            reload_rules = 0;
            pthread_mutex_unlock(&SaganRulesLoadedMutex);

        }

    /************/
    /* Log only */
    /************/

    else if ( config->dynamic_load_type == 1 )
        {

            Sagan_Log(NORMAL, "Detected dynamic signature '%s'. Sagan would automatically load '%s' but the 'dynamic_load' processor is set to 'log_only'.", RuleBody[rule_position].s_msg, RuleBody[rule_position].DynamicLoad.dynamic_ruleset);

        }

    /**************/
    /* Alert only */
    /**************/

    else if ( config->dynamic_load_type == 2 )
        {

            Sagan_Log(NORMAL, "Detected dynamic signature '%s'. Sagan would automatically load '%s' but the 'dynamic_load' processor is set to 'alert'.", RuleBody[rule_position].s_msg, RuleBody[rule_position].DynamicLoad.dynamic_ruleset);


            gettimeofday(&tp, 0);

            Send_Alert(SaganProcSyslog_LOCAL,
                       NULL,
                       processor_info_engine,
                       ip_src,
                       ip_dst,
                       "",
                       "",
                       config->default_proto,
                       RuleBody[rule_position].s_sid,
                       config->default_port,
                       config->default_port,
                       rule_position, tp, NULL, 0 );

        }

    return(0);

}
