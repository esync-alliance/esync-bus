
#include "tests/tests.h"
#include "tests/full-test.h"
#include "tests/cases.h"
#include "lib/debug.h"
#include <libxl4bus/low_level.h>
#include "client_message.h"

#define MESSAGE \
"07-03:16:33:18.812 send_message:ws_xl4bus.c:67 [main] BUS SND 0x2" \
"c0aa070 { type: FCT_BUS_MESSAGE_QUERY_UPDATE_RESPONSE, body: { campaigns: [ { id: 123" \
"9, release-notes: {\"version\":2,\"title\":{\"en\":\"DDCU1-2\",\"zh\":\"DDCU" \
"1-2\"},\"info\":{\"zh\":\"请等待\"}}, targets: [ { package: { name: GW-ECU-" \
"3610315-DB01-0x0056, type: \\/GW\\/ECU\\/3610315-DB01, version: 3610" \
"811-DB012003, current-version: 3610811-DB012003, version-list: { " \
"3610811-DB012003: { downloaded: true, file: \\/fota\\/download\\/GW-" \
"ECU-3610315-DB01-0x0056-3610811-DB012003.x, sha-256: VTmtgLu1MWYn" \
"3rb7k7EsxvXnBHSTAsScfa2Qz3LdC\\/c=, manifest: [ xl4_pkg_update_man" \
"ifest, [ package, GW-ECU-3610315-DB01-0x0056 ], [ name, DDCU ], [" \
" type, \\/GW\\/ECU\\/3610315-DB01 ], [ version, 3610811-DB012003 ], " \
"[ hardware-statement, 'make:FAW' AND 'model:C229' AND 'year:2020'" \
" AND 'partNumber:3610315-DB01' ], [ rollback, [ user-agent-contro" \
"lled, true ] ], [ empty, false ], [ delta-reference, 3610811-DB01" \
"2003 ], [ ign-mode, ON ], [ ign-timeout, 120 ], [ ecuid, 0x0056 ]" \
" ], length: 88255 } }, rollback-versions: [ 3610811-DB012001 ], t" \
"erminal-failure: false, update-status: 90, expiration: 2020-06-20" \
"T00:00:00.000Z, update-progress: { }, download-consent: { state: " \
"3 } } } ], policies: [ { type: fontana:vehicle_speed, kmph: 0 }, " \
"{ type: fontana:engine_speed, rpm: 0 }, { type: TIME_WINDOW, sour" \
"ce: user }, { type: fontana:start_stop_not_running }, { type: SIN" \
"GLE_USE_CAMPAIGN }, { type: fontana:parked }, { type: fontana:upg" \
"rade_time, seconds: 240, computed-seconds: 240 }, { type: fontana" \
":epb_locked }, { type: fontana:power_state_of_charge, percentage:" \
" 20 } ], executing: false, policy-satisfaction: { } }, { id: 1339" \
", release-notes: {\"version\":2,\"title\":{\"en\":\"SCM_1\",\"zh\":\"SCM_1\"}" \
",\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}}, targets: [ { package:" \
" { name: GW-ECU-3610350-DB01-0x0053, type: \\/GW\\/ECU\\/3610350-DB0" \
"1, version: 3610816-DB011003, current-version: 3610816-DB011003, " \
"version-list: { 3610816-DB011003: { downloaded: true, file: \\/fot" \
"a\\/download\\/GW-ECU-3610350-DB01-0x0053-3610816-DB011003.x, sha-2" \
"56: an4W6vX916xuHLVFAGLvLrRHR4eB0GafNUx5HRP864k=, manifest: [ xl4" \
"_pkg_update_manifest, [ package, GW-ECU-3610350-DB01-0x0053 ], [ " \
"name, SCM ], [ type, \\/GW\\/ECU\\/3610350-DB01 ], [ version, 361081" \
"6-DB011003 ], [ hardware-statement, 'make:FAW' AND 'model:C229' A" \
"ND 'year:2020' AND 'partNumber:3610350-DB01' ], [ rollback, [ use" \
"r-agent-controlled, true ] ], [ empty, false ], [ delta-reference" \
", 3610816-DB011003 ], [ ign-mode, ON ], [ ign-timeout, 120 ], [ e" \
"cuid, 0x0053 ] ], length: 35650 } }, rollback-versions: [ 3610816" \
"-DB011004 ], terminal-failure: false, update-status: 90, expirati" \
"on: 2020-07-02T00:00:00.000Z, update-progress: { }, download-cons" \
"ent: { state: 3 } } } ], policies: [ { type: fontana:vehicle_spee" \
"d, kmph: 0 }, { type: fontana:engine_speed, rpm: 0 }, { type: TIM" \
"E_WINDOW, source: user }, { type: fontana:start_stop_not_running " \
"}, { type: SINGLE_USE_CAMPAIGN }, { type: fontana:parked }, { typ" \
"e: fontana:upgrade_time, seconds: 240, computed-seconds: 240 }, {" \
" type: fontana:epb_locked }, { type: fontana:power_state_of_charg" \
"e, percentage: 20 } ], executing: false, policy-satisfaction: { }" \
" }, { id: 1350, release-notes: {\"version\":2,\"title\":{\"en\":\"TBOX_4" \
"00X\",\"zh\":\"TBOX_400X\"},\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}}," \
" targets: [ { package: { name: GW-ECU-7905070-DB01-0x0010, type: " \
"\\/GW\\/ECU\\/7905070-DB01, version: 7905801-DB01400X, current-versi" \
"on: 7905801-DB01400X, version-list: { 7905801-DB01400X: { downloa" \
"ded: true, file: \\/fota\\/download\\/GW-ECU-7905070-DB01-0x0010-790" \
"5801-DB01400X.x, sha-256: fMb73ZJiqKyOq4G3mFcATJgVlM4g5icai5maxQH" \
"nKyI=, manifest: [ xl4_pkg_update_manifest, [ package, GW-ECU-790" \
"5070-DB01-0x0010 ], [ name, TBOX ], [ type, \\/GW\\/ECU\\/7905070-DB" \
"01 ], [ version, 7905801-DB01400X ], [ hardware-statement, 'make:" \
"FAW' AND 'model:C229' AND 'year:2020' AND 'partNumber:7905070-DB0" \
"1' ], [ rollback, [ user-agent-controlled, true ] ], [ empty, fal" \
"se ], [ delta-reference, 7905801-DB01400X ], [ ign-mode, ON ], [ " \
"ign-timeout, 600 ], [ ecuid, 0x0010 ] ], length: 95681863 } }, ro" \
"llback-versions: [ 7905801-DB014002 ], terminal-failure: false, u" \
"pdate-status: 90, expiration: 2020-07-04T00:00:00.000Z, update-pr" \
"ogress: { }, download-consent: { state: 0, expiration: 2020-07-04" \
"T07:43:30.000Z } } } ], policies: [ { type: fontana:vehicle_speed" \
", kmph: 0 }, { type: fontana:engine_speed, rpm: 0 }, { type: TIME" \
"_WINDOW, source: user }, { type: fontana:start_stop_not_running }" \
", { type: SINGLE_USE_CAMPAIGN }, { type: fontana:parked }, { type" \
": fontana:upgrade_time, seconds: 1200, computed-seconds: 1200 }, " \
"{ type: fontana:epb_locked }, { type: fontana:power_state_of_char" \
"ge, percentage: 20 } ], executing: false, policy-satisfaction: { " \
"} }, { id: 1323, release-notes: {\"version\":2,\"title\":{\"en\":\"DSCU_" \
"1\",\"zh\":\"DSCU_1\"},\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}}, targ" \
"ets: [ { package: { name: GW-ECU-3610815-DB03-0x0054, type: \\/GW\\" \
"/ECU\\/3610815-DB03, version: 3610822-DB033002, current-version: 3" \
"610822-DB033002, version-list: { 3610822-DB033002: { downloaded: " \
"true, file: \\/fota\\/download\\/GW-ECU-3610815-DB03-0x0054-3610822-" \
"DB033002.x, sha-256: hdPaIyt9q79IHwHLt30pSNnlehgRuAc6r\\/rOYm06S9M" \
"=, manifest: [ xl4_pkg_update_manifest, [ package, GW-ECU-3610815" \
"-DB03-0x0054 ], [ name, DSCU ], [ type, \\/GW\\/ECU\\/3610815-DB03 ]" \
", [ version, 3610822-DB033002 ], [ hardware-statement, 'make:FAW'" \
" AND 'model:C229' AND 'year:2020' AND 'partNumber:3610815-DB03' ]" \
", [ rollback, [ user-agent-controlled, true ] ], [ empty, false ]" \
", [ delta-reference, 3610822-DB033002 ], [ ign-mode, ON ], [ ign-" \
"timeout, 120 ], [ ecuid, 0x0054 ] ], length: 55220 } }, rollback-" \
"versions: [ 3610822-DB031007 ], terminal-failure: false, update-s" \
"tatus: 90, expiration: 2020-07-01T00:00:00.000Z, update-progress:" \
" { }, download-consent: { state: 3 } } } ], policies: [ { type: f" \
"ontana:vehicle_speed, kmph: 0 }, { type: fontana:engine_speed, rp" \
"m: 0 }, { type: TIME_WINDOW, source: user }, { type: fontana:star" \
"t_stop_not_running }, { type: SINGLE_USE_CAMPAIGN }, { type: font" \
"ana:parked }, { type: fontana:upgrade_time, seconds: 240, compute" \
"d-seconds: 240 }, { type: fontana:epb_locked }, { type: fontana:p" \
"ower_state_of_charge, percentage: 20 } ], executing: false, polic" \
"y-satisfaction: { } }, { id: 1346, release-notes: {\"version\":2,\"t" \
"itle\":{\"en\":\"ACM_2\",\"zh\":\"ACM_2\"},\"info\":{\"en\":\"updating\",\"zh\":\"u" \
"pdating\"}}, targets: [ { package: { name: GW-ECU-3627015-DB01-0x0" \
"034, type: \\/GW\\/ECU\\/3627015-DB01, version: KA.ACM.16, current-v" \
"ersion: KA.ACM.16, version-list: { KA.ACM.16: { downloaded: true," \
" file: \\/fota\\/download\\/GW-ECU-3627015-DB01-0x0034-KA.ACM.16.x, " \
"sha-256: zPJBcf1YKAHtPXFsyGVPGbGi7vLeS9SQUwoZk3ysjs4=, manifest: " \
"[ xl4_pkg_update_manifest, [ package, GW-ECU-3627015-DB01-0x0034 " \
"], [ name, ACM ], [ type, \\/GW\\/ECU\\/3627015-DB01 ], [ version, K" \
"A.ACM.16 ], [ hardware-statement, 'make:FAW' AND 'model:C229' AND" \
" 'year:2020' AND 'partNumber:3627015-DB01' ], [ rollback, [ user-" \
"agent-controlled, true ] ], [ empty, false ], [ delta-reference, " \
"KA.ACM.16 ], [ ign-mode, ON ], [ ign-timeout, 120 ], [ ecuid, 0x0" \
"034 ] ], length: 43459 } }, rollback-versions: [ KA.ACM.15 ], ter" \
"minal-failure: false, update-status: 90, expiration: 2020-07-04T0" \
"0:00:00.000Z, update-progress: { }, download-consent: { state: 0," \
" expiration: 2020-07-04T01:40:36.000Z } } } ], policies: [ { type" \
": fontana:vehicle_speed, kmph: 0 }, { type: fontana:engine_speed," \
" rpm: 0 }, { type: TIME_WINDOW, source: user }, { type: fontana:s" \
"tart_stop_not_running }, { type: SINGLE_USE_CAMPAIGN }, { type: f" \
"ontana:parked }, { type: fontana:upgrade_time, seconds: 240, comp" \
"uted-seconds: 240 }, { type: fontana:epb_locked }, { type: fontan" \
"a:power_state_of_charge, percentage: 20 } ], executing: false, po" \
"licy-satisfaction: { } }, { id: 1227, release-notes: {\"version\":2" \
",\"title\":{\"en\":\"HUD-2-1\",\"zh\":\"HUD-2-1\"},\"info\":{\"zh\":\"升级任务\"}}, t" \
"argets: [ { package: { name: GW-ECU-3830010-DB05-0x0061, type: \\/" \
"GW\\/ECU\\/3830010-DB05, version: MV1.1CV1.1, current-version: MV1." \
"0CV1.1, version-list: { MV1.1CV1.1: { downloaded: false, sha-256:" \
" Djj3kZif0tjE\\/cspaxBGDs1VkhYF14tWWniYeSAZFic=, manifest: [ xl4_p" \
"kg_update_manifest, [ package, GW-ECU-3830010-DB05-0x0061 ], [ na" \
"me, HUD ], [ type, \\/GW\\/ECU\\/3830010-DB05 ], [ version, MV1.1CV1" \
".1 ], [ hardware-statement, 'make:FAW' AND 'model:C229' AND 'year" \
":2020' AND 'partNumber:3830010-DB05' ], [ rollback, [ user-agent-" \
"controlled, true ] ], [ empty, false ], [ delta-reference, MV1.1C" \
"V1.1 ], [ ign-mode, ON ], [ ign-timeout, 360 ], [ ecuid, 0x0061 ]" \
" ], length: 465443 } }, rollback-version: MV1.0CV8.8, rollback-ve" \
"rsions: [ MV1.0CV8.8 ], terminal-failure: true, update-status: 40" \
", expiration: 2020-06-19T00:00:00.000Z, update-progress: { }, dow" \
"nload-consent: { state: 3 } } } ], policies: [ { type: fontana:ve" \
"hicle_speed, kmph: 0 }, { type: fontana:engine_speed, rpm: 0 }, {" \
" type: TIME_WINDOW, source: user }, { type: fontana:start_stop_no" \
"t_running }, { type: SINGLE_USE_CAMPAIGN }, { type: fontana:parke" \
"d }, { type: fontana:upgrade_time, seconds: 720, computed-seconds" \
": 720 }, { type: fontana:epb_locked }, { type: fontana:power_stat" \
"e_of_charge, percentage: 20 } ], executing: false, policy-satisfa" \
"ction: { } }, { id: 1327, release-notes: {\"version\":2,\"title\":{\"e" \
"n\":\"ACU_2\",\"zh\":\"ACU_2\"},\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}" \
"}, targets: [ { package: { name: GW-ECU-3607115-DB01-0x0035, type" \
": \\/GW\\/ECU\\/3607115-DB01, version: 3607801-DB012002, current-ver" \
"sion: 3607801-DB012002, version-list: { 3607801-DB012002: { downl" \
"oaded: true, file: \\/fota\\/download\\/GW-ECU-3607115-DB01-0x0035-3" \
"607801-DB012002.x, sha-256: DYxKSJ2B7itWEqLemlI12\\/uUqifjxSWtesYk" \
"NRr8HG8=, manifest: [ xl4_pkg_update_manifest, [ package, GW-ECU-" \
"3607115-DB01-0x0035 ], [ name, ACU ], [ type, \\/GW\\/ECU\\/3607115-" \
"DB01 ], [ version, 3607801-DB012002 ], [ hardware-statement, 'mak" \
"e:FAW' AND 'model:C229' AND 'year:2020' AND 'partNumber:3607115-D" \
"B01' ], [ rollback, [ user-agent-controlled, true ] ], [ empty, f" \
"alse ], [ delta-reference, 3607801-DB012002 ], [ ign-mode, ON ], " \
"[ ign-timeout, 180 ], [ ecuid, 0x0035 ] ], length: 173253 } }, ro" \
"llback-versions: [ 3607801-DB013001 ], terminal-failure: false, u" \
"pdate-status: 90, expiration: 2020-07-01T00:00:00.000Z, update-pr" \
"ogress: { }, download-consent: { state: 3 } } } ], policies: [ { " \
"type: fontana:vehicle_speed, kmph: 0 }, { type: fontana:engine_sp" \
"eed, rpm: 0 }, { type: TIME_WINDOW, source: user }, { type: fonta" \
"na:start_stop_not_running }, { type: SINGLE_USE_CAMPAIGN }, { typ" \
"e: fontana:parked }, { type: fontana:upgrade_time, seconds: 360, " \
"computed-seconds: 360 }, { type: fontana:epb_locked }, { type: fo" \
"ntana:power_state_of_charge, percentage: 20 } ], executing: false" \
", policy-satisfaction: { } }, { id: 1240, release-notes: {\"versio" \
"n\":2,\"title\":{\"en\":\"ADB11-2\",\"zh\":\"ADB11-2\"},\"info\":{\"zh\":\"成功了\"}}" \
", targets: [ { package: { name: GW-ECU-3711025-DB03-0x0079, type:" \
" \\/GW\\/ECU\\/3711025-DB03, version: SV1.4, current-version: SV1.4," \
" version-list: { SV1.4: { downloaded: true, file: \\/fota\\/downloa" \
"d\\/GW-ECU-3711025-DB03-0x0079-SV1.4.x, sha-256: d9oBYuCFrML0drr2F" \
"K06TYUWIxhVfJ\\/aLRRKb8OfORY=, manifest: [ xl4_pkg_update_manifest" \
", [ package, GW-ECU-3711025-DB03-0x0079 ], [ name, ADBL ], [ type" \
", \\/GW\\/ECU\\/3711025-DB03 ], [ version, SV1.4 ], [ hardware-state" \
"ment, 'make:FAW' AND 'model:C229' AND 'year:2020' AND 'partNumber" \
":3711025-DB03' ], [ rollback, [ user-agent-controlled, true ] ], " \
"[ empty, false ], [ delta-reference, SV1.4 ], [ ign-mode, ON ], [" \
" ign-timeout, 120 ], [ ecuid, 0x0079 ] ], length: 52430 } }, roll" \
"back-versions: [ SV1.3 ], terminal-failure: false, update-status:" \
" 90, expiration: 2020-06-20T00:00:00.000Z, update-progress: { }, " \
"download-consent: { state: 3 } } } ], policies: [ { type: fontana" \
":vehicle_speed, kmph: 0 }, { type: fontana:engine_speed, rpm: 0 }" \
", { type: TIME_WINDOW, source: user }, { type: fontana:start_stop" \
"_not_running }, { type: SINGLE_USE_CAMPAIGN }, { type: fontana:pa" \
"rked }, { type: fontana:upgrade_time, seconds: 240, computed-seco" \
"nds: 240 }, { type: fontana:epb_locked }, { type: fontana:power_s" \
"tate_of_charge, percentage: 20 } ], executing: false, policy-sati" \
"sfaction: { } }, { id: 1254, release-notes: {\"version\":2,\"title\":" \
"{\"en\":\"5包升级-预约\",\"zh\":\"5包升级-预约\"},\"info\":{\"en\":\"5包升级-预约\",\"zh\":\"5包升级" \
"-预约\"}}, targets: [ { package: { name: GW-ECU-3629100-DB01-0x0071," \
" type: \\/GW\\/ECU\\/3629100-DB01, version: SW0204200526, current-ve" \
"rsion: SW0204200526, version-list: { SW0204200526: { downloaded: " \
"true, sha-256: mqMfZudI0F9BimPyFLkCF5vJL\\/kAAWeFT+ebk3ix7lw=, man" \
"ifest: [ xl4_pkg_update_manifest, [ package, GW-ECU-3629100-DB01-" \
"0x0071 ], [ name, ADV ], [ type, \\/GW\\/ECU\\/3629100-DB01 ], [ ver" \
"sion, SW0204200526 ], [ hardware-statement, 'make:FAW' AND 'model" \
":C229' AND 'year:2020' AND 'partNumber:3629100-DB01' ], [ rollbac" \
"k, [ user-agent-controlled, true ] ], [ empty, false ], [ delta-r" \
"eference, SW0204200526 ], [ ign-mode, ON ], [ ign-timeout, 300 ]," \
" [ ecuid, 0x0071 ] ], length: 0 } }, rollback-versions: [ SW02042" \
"00526 ], terminal-failure: false, update-status: 90, expiration: " \
"2020-06-29T00:00:00.000Z, update-progress: { }, download-consent:" \
" { state: 1 } } }, { package: { name: GW-ECU-3710060-DB01-0x00F0," \
" type: \\/GW\\/ECU\\/3710060-DB01, version: 3710060-DB010005, curren" \
"t-version: 3710060-DB010005, version-list: { 3710060-DB010005: { " \
"downloaded: true, sha-256: Hcm0bk5bi+5yf7wXWBtvrMtnZeTI7fjhb5g\\/n" \
"E67\\/pw=, manifest: [ xl4_pkg_update_manifest, [ package, GW-ECU-" \
"3710060-DB01-0x00F0 ], [ name, ALU ], [ type, \\/GW\\/ECU\\/3710060-" \
"DB01 ], [ version, 3710060-DB010005 ], [ hardware-statement, 'mak" \
"e:FAW' AND 'model:C229' AND 'year:2020' AND 'partNumber:3710060-D" \
"B01' ], [ rollback, [ user-agent-controlled, true ] ], [ empty, f" \
"alse ], [ delta-reference, 3710060-DB010005 ], [ ign-mode, ON ], " \
"[ ign-timeout, 120 ], [ ecuid, 0x00F0 ] ], length: 0 } }, rollbac" \
"k-versions: [ 3710060-DB010005 ], terminal-failure: false, update" \
"-status: 90, expiration: 2020-06-29T00:00:00.000Z, update-progres" \
"s: { }, download-consent: { state: 1 } } }, { package: { name: GW" \
"-ECU-3830015-DB05-0x0064, type: \\/GW\\/ECU\\/3830015-DB05, version:" \
" 1031000000000000, current-version: 1031000000000000, version-lis" \
"t: { 1031000000000000: { downloaded: true, file: \\/fota\\/download" \
"\\/GW-ECU-3830015-DB05-0x0064-1031000000000000.x, sha-256: 7ahKy29" \
"2lYBixG3ly8JIA9SFvyrteLFRruXjxU+rXCU=, manifest: [ xl4_pkg_update" \
"_manifest, [ package, GW-ECU-3830015-DB05-0x0064 ], [ name, FDM ]" \
", [ type, \\/GW\\/ECU\\/3830015-DB05 ], [ version, 1031000000000000 " \
"], [ hardware-statement, 'make:FAW' AND 'model:C229' AND 'year:20" \
"20' AND 'partNumber:3830015-DB05' ], [ rollback, [ user-agent-con" \
"trolled, true ] ], [ empty, false ], [ delta-reference, 103100000" \
"0000000 ], [ ign-mode, ON ], [ ign-timeout, 120 ], [ ecuid, 0x006" \
"4 ] ], length: 78392 } }, rollback-versions: [ 1030             ]" \
", terminal-failure: false, update-status: 90, expiration: 2020-06" \
"-29T00:00:00.000Z, update-progress: { }, download-consent: { stat" \
"e: 3 } } }, { package: { name: GW-ECU-1504270-DB01-0x0033, type: " \
"\\/GW\\/ECU\\/1504270-DB01, version: KA.EGSM.06, current-version: KA" \
".EGSM.02      , version-list: { KA.EGSM.06: { downloaded: false, " \
"sha-256: eWPNWozH4UmxEbMOASzKDD3yZS8R3vSshJ6gzoLyw3I=, manifest: " \
"[ xl4_pkg_update_manifest, [ package, GW-ECU-1504270-DB01-0x0033 " \
"], [ name, EGSM ], [ type, \\/GW\\/ECU\\/1504270-DB01 ], [ version, " \
"KA.EGSM.06 ], [ hardware-statement, 'make:FAW' AND 'model:C229' A" \
"ND 'year:2020' AND 'partNumber:1504270-DB01' ], [ rollback, [ use" \
"r-agent-controlled, true ] ], [ empty, false ], [ delta-reference" \
", KA.EGSM.06 ], [ ign-mode, ON ], [ ign-timeout, 120 ], [ ecuid, " \
"0x0033 ] ], length: 28588 } }, rollback-versions: [ KA.EGSM.04 ]," \
" terminal-failure: false, update-status: 80, expiration: 2020-06-" \
"29T00:00:00.000Z, update-progress: { }, download-consent: { state" \
": 3 } } } ], policies: [ { type: fontana:vehicle_speed, kmph: 0 }" \
", { type: fontana:engine_speed, rpm: 0 }, { type: TIME_WINDOW, so" \
"urce: user }, { type: fontana:start_stop_not_running }, { type: S" \
"INGLE_USE_CAMPAIGN }, { type: fontana:parked }, { type: fontana:u" \
"pgrade_time, seconds: 2040, computed-seconds: 2040 }, { type: fon" \
"tana:epb_locked }, { type: fontana:power_state_of_charge, percent" \
"age: 20 } ], executing: false, policy-satisfaction: { } }, { id: " \
"1320, release-notes: {\"version\":2,\"title\":{\"en\":\"RLDCU_2\",\"zh\":\"R" \
"LDCU_2\"},\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}}, targets: [ { " \
"package: { name: GW-ECU-3610325-DB01-0x0058, type: \\/GW\\/ECU\\/361" \
"0325-DB01, version: 3610813-DB012003, current-version: NULL, vers" \
"ion-list: { 3610813-DB012003: { downloaded: false, sha-256: KBvxF" \
"1ITFpM2Vqu3U+DLC9J3tLlWdv5mYI4261Khsro=, manifest: [ xl4_pkg_upda" \
"te_manifest, [ package, GW-ECU-3610325-DB01-0x0058 ], [ name, RLD" \
"CU ], [ type, \\/GW\\/ECU\\/3610325-DB01 ], [ version, 3610813-DB012" \
"003 ], [ hardware-statement, 'make:FAW' AND 'model:C229' AND 'yea" \
"r:2020' AND 'partNumber:3610325-DB01' ], [ rollback, [ user-agent" \
"-controlled, true ] ], [ empty, false ], [ delta-reference, 36108" \
"13-DB012003 ], [ ign-mode, ON ], [ ign-timeout, 120 ], [ ecuid, 0" \
"x0058 ] ], length: 95299 } }, rollback-version: NULL, rollback-ve" \
"rsions: [ NULL ], terminal-failure: false, update-status: 100, ex" \
"piration: 2020-07-01T00:00:00.000Z, update-progress: { }, downloa" \
"d-consent: { state: 3 } } } ], policies: [ { type: fontana:vehicl" \
"e_speed, kmph: 0 }, { type: fontana:engine_speed, rpm: 0 }, { typ" \
"e: TIME_WINDOW, source: user }, { type: fontana:start_stop_not_ru" \
"nning }, { type: SINGLE_USE_CAMPAIGN }, { type: fontana:parked }," \
" { type: fontana:upgrade_time, seconds: 240, computed-seconds: 24" \
"0 }, { type: fontana:epb_locked }, { type: fontana:power_state_of" \
"_charge, percentage: 20 } ], executing: false, policy-satisfactio" \
"n: { } }, { id: 1220, release-notes: {\"version\":2,\"title\":{\"en\":\"" \
"RLCU-1-2\",\"zh\":\"RLCU-1-2\"},\"info\":{\"zh\":\"成功\"}}, targets: [ { pack" \
"age: { name: GW-ECU-3710095-DB01-0x005F, type: \\/GW\\/ECU\\/3710095" \
"-DB01, version: BV06-1, current-version: BV06-1, version-list: { " \
"BV06-1: { downloaded: true, file: \\/fota\\/download\\/GW-ECU-371009" \
"5-DB01-0x005F-BV06-1.x, sha-256: bXK8CnRdCG4ah3E88uLnowkf46nd6I5p" \
"sYbwHqAbg7w=, manifest: [ xl4_pkg_update_manifest, [ package, GW-" \
"ECU-3710095-DB01-0x005F ], [ name, RLCU ], [ type, \\/GW\\/ECU\\/371" \
"0095-DB01 ], [ version, BV06-1 ], [ hardware-statement, 'make:FAW" \
"' AND 'model:C229' AND 'year:2020' AND 'partNumber:3710095-DB01' " \
"], [ rollback, [ user-agent-controlled, true ] ], [ empty, false " \
"], [ delta-reference, BV06-1 ], [ ign-mode, ON ], [ ign-timeout, " \
"120 ], [ ecuid, 0x005F ] ], length: 40671 } }, rollback-versions:" \
" [ BV06 ], terminal-failure: false, update-status: 90, expiration" \
": 2020-06-18T00:00:00.000Z, update-progress: { }, download-consen" \
"t: { state: 3 } } } ], policies: [ { type: fontana:vehicle_speed," \
" kmph: 0 }, { type: fontana:engine_speed, rpm: 0 }, { type: TIME_" \
"WINDOW, source: user }, { type: fontana:start_stop_not_running }," \
" { type: SINGLE_USE_CAMPAIGN }, { type: fontana:parked }, { type:" \
" fontana:upgrade_time, seconds: 240, computed-seconds: 240 }, { t" \
"ype: fontana:epb_locked }, { type: fontana:power_state_of_charge," \
" percentage: 20 } ], executing: false, policy-satisfaction: { } }" \
", { id: 1314, release-notes: {\"version\":2,\"title\":{\"en\":\"IFC1\",\"z" \
"h\":\"IFC1\"},\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}}, targets: [ " \
"{ package: { name: GW-ECU-3616215-DB05-0x0074, type: \\/GW\\/ECU\\/3" \
"616215-DB05, version: 2001, current-version: 2001, version-list: " \
"{ 2001: { downloaded: true, file: \\/fota\\/download\\/GW-ECU-361621" \
"5-DB05-0x0074-2001.x, sha-256: ObYBuj8CPHriQeMkg1pzKaEZJ7SeVTteFk" \
"GEK4xWQqM=, manifest: [ xl4_pkg_update_manifest, [ package, GW-EC" \
"U-3616215-DB05-0x0074 ], [ name, IFC ], [ type, \\/GW\\/ECU\\/361621" \
"5-DB05 ], [ version, 2001 ], [ hardware-statement, 'make:FAW' AND" \
" 'model:C229' AND 'year:2020' AND 'partNumber:3616215-DB05' ], [ " \
"rollback, [ user-agent-controlled, true ] ], [ empty, false ], [ " \
"delta-reference, 2001 ], [ ign-mode, ON ], [ ign-timeout, 180 ], " \
"[ ecuid, 0x0074 ] ], length: 383749 } }, rollback-versions: [ 200" \
"2 ], terminal-failure: false, update-status: 90, expiration: 2020" \
"-07-01T00:00:00.000Z, update-progress: { }, download-consent: { s" \
"tate: 3 } } } ], policies: [ { type: fontana:vehicle_speed, kmph:" \
" 0 }, { type: fontana:engine_speed, rpm: 0 }, { type: TIME_WINDOW" \
", source: user }, { type: fontana:start_stop_not_running }, { typ" \
"e: SINGLE_USE_CAMPAIGN }, { type: fontana:parked }, { type: fonta" \
"na:upgrade_time, seconds: 360, computed-seconds: 360 }, { type: f" \
"ontana:epb_locked }, { type: fontana:power_state_of_charge, perce" \
"ntage: 20 } ], executing: false, policy-satisfaction: { } }, { id" \
": 1348, release-notes: {\"version\":2,\"title\":{\"en\":\"IVI1\",\"zh\":\"IV" \
"I1\"},\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}}, targets: [ { pack" \
"age: { name: GW-ECU-7901010-DB01-0x0020, type: \\/GW\\/ECU\\/7901010" \
"-DB01, version: C229IVI-02.00.00, current-version: C229IVI-02.00." \
"00, version-list: { C229IVI-02.00.00: { downloaded: true, file: \\" \
"/fota\\/download\\/GW-ECU-7901010-DB01-0x0020-C229IVI-02.00.00.x, s" \
"ha-256: DtJd6h\\/eVukiPWCpQCanCUchFgOYZMaPEvIH32nRlDo=, manifest: " \
"[ xl4_pkg_update_manifest, [ package, GW-ECU-7901010-DB01-0x0020 " \
"], [ name, IVI ], [ type, \\/GW\\/ECU\\/7901010-DB01 ], [ version, C" \
"229IVI-02.00.00 ], [ hardware-statement, 'make:FAW' AND 'model:C2" \
"29' AND 'year:2020' AND 'partNumber:7901010-DB01' ], [ rollback, " \
"[ user-agent-controlled, true ] ], [ empty, false ], [ delta-refe" \
"rence, C229IVI-02.00.00 ], [ ign-mode, ON ], [ ign-timeout, 1800 " \
"], [ ecuid, 0x0020 ] ], length: 1851703469 } }, rollback-versions" \
": [ C229IVI-01.09.03 ], terminal-failure: false, update-status: 9" \
"0, expiration: 2020-07-04T00:00:00.000Z, update-progress: { }, do" \
"wnload-consent: { state: 0, expiration: 2020-07-04T03:08:36.000Z " \
"} } } ], policies: [ { type: fontana:vehicle_speed, kmph: 0 }, { " \
"type: fontana:engine_speed, rpm: 0 }, { type: TIME_WINDOW, source" \
": user }, { type: fontana:start_stop_not_running }, { type: SINGL" \
"E_USE_CAMPAIGN }, { type: fontana:parked }, { type: fontana:upgra" \
"de_time, seconds: 3600, computed-seconds: 3600 }, { type: fontana" \
":epb_locked }, { type: fontana:power_state_of_charge, percentage:" \
" 20 } ], executing: false, policy-satisfaction: { } }, { id: 1354" \
", release-notes: {\"version\":2,\"title\":{\"en\":\"EPS_1\",\"zh\":\"EPS_1\"}" \
",\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}}, targets: [ { package:" \
" { name: GW-ECU-3418310-DB01-0x0042, type: \\/GW\\/ECU\\/3418310-DB0" \
"1, version: 3418801-DB012006, current-version: 3418801-DB013008, " \
"version-list: { 3418801-DB012006: { downloaded: true, file: \\/fot" \
"a\\/download\\/GW-ECU-3418310-DB01-0x0042-3418801-DB012006.x, sha-2" \
"56: IbIaQjrxxqNUZJbPU1ZgNIxnwSxgP4Sogtnccf\\/7V9M=, manifest: [ xl" \
"4_pkg_update_manifest, [ package, GW-ECU-3418310-DB01-0x0042 ], [" \
" name, EPS ], [ type, \\/GW\\/ECU\\/3418310-DB01 ], [ version, 34188" \
"01-DB012006 ], [ hardware-statement, 'make:FAW' AND 'model:C229' " \
"AND 'year:2020' AND 'partNumber:3418310-DB01' ], [ rollback, [ us" \
"er-agent-controlled, true ] ], [ empty, false ], [ delta-referenc" \
"e, 3418801-DB012006 ], [ ign-mode, ON ], [ ign-timeout, 360 ], [ " \
"ecuid, 0x0042 ] ], length: 179349 } }, rollback-versions: [ 34188" \
"01-DB013008 ], terminal-failure: false, update-status: 50, expira" \
"tion: 2020-07-04T00:00:00.000Z, update-progress: { update-window:" \
" { } }, download-consent: { state: 0, expiration: 2020-07-04T08:2" \
"3:35.000Z } } } ], policies: [ { type: fontana:vehicle_speed, kmp" \
"h: 0 }, { type: fontana:engine_speed, rpm: 0 }, { type: TIME_WIND" \
"OW, source: user }, { type: fontana:start_stop_not_running }, { t" \
"ype: SINGLE_USE_CAMPAIGN }, { type: fontana:parked }, { type: fon" \
"tana:upgrade_time, seconds: 720, computed-seconds: 720 }, { type:" \
" fontana:epb_locked }, { type: fontana:power_state_of_charge, per" \
"centage: 20 } ], executing: true, policy-satisfaction: { download" \
": { reference: 125, response: [ ], satisfied: true, last-received" \
"-at: 2020-07-03T08:23:34.000Z } } }, { id: 1217, release-notes: {" \
"\"version\":2,\"title\":{\"en\":\"RMAR\",\"zh\":\"RMAR\"},\"info\":{\"zh\":\"升级\"}}" \
", targets: [ { package: { name: GW-ECU-3748030-DB05-0x005D, type:" \
" \\/GW\\/ECU\\/3748030-DB05, version: 3748802-DB323010, current-vers" \
"ion: 3748802-DB323010, version-list: { 3748802-DB323010: { downlo" \
"aded: true, file: \\/fota\\/download\\/GW-ECU-3748030-DB05-0x005D-37" \
"48802-DB323010.x, sha-256: JgDYTz6WCxStH7WzdzJoWclRcrCMeymztFYvp3" \
"t3Mp4=, manifest: [ xl4_pkg_update_manifest, [ package, GW-ECU-37" \
"48030-DB05-0x005D ], [ name, RMAR ], [ type, \\/GW\\/ECU\\/3748030-D" \
"B05 ], [ version, 3748802-DB323010 ], [ hardware-statement, 'make" \
":FAW' AND 'model:C229' AND 'year:2020' AND 'partNumber:3748030-DB" \
"05' ], [ rollback, [ user-agent-controlled, true ] ], [ empty, fa" \
"lse ], [ delta-reference, 3748802-DB323010 ], [ ign-mode, ON ], [" \
" ign-timeout, 180 ], [ ecuid, 0x005D ] ], length: 23084 } }, roll" \
"back-versions: [ 3748802-DB053002 ], terminal-failure: false, upd" \
"ate-status: 90, expiration: 2020-06-18T00:00:00.000Z, update-prog" \
"ress: { }, download-consent: { state: 3 } } } ], policies: [ { ty" \
"pe: fontana:vehicle_speed, kmph: 0 }, { type: fontana:engine_spee" \
"d, rpm: 0 }, { type: TIME_WINDOW, source: user }, { type: fontana" \
":start_stop_not_running }, { type: SINGLE_USE_CAMPAIGN }, { type:" \
" fontana:parked }, { type: fontana:upgrade_time, seconds: 360, co" \
"mputed-seconds: 360 }, { type: fontana:epb_locked }, { type: font" \
"ana:power_state_of_charge, percentage: 20 } ], executing: false, " \
"policy-satisfaction: { } }, { id: 1229, release-notes: {\"version\"" \
":2,\"title\":{\"en\":\"PSCU-1-2\",\"zh\":\"PSCU-1-2\"},\"info\":{\"zh\":\"请等待\"}}" \
", targets: [ { package: { name: GW-ECU-3610820-DB03-0x005B, type:" \
" \\/GW\\/ECU\\/3610820-DB03, version: 3610823-DB031006, current-vers" \
"ion: 3610823-DB031006, version-list: { 3610823-DB031006: { downlo" \
"aded: true, file: \\/fota\\/download\\/GW-ECU-3610820-DB03-0x005B-36" \
"10823-DB031006.x, sha-256: qVa78Z9yM+Uf+ytp2NZ3vTAtm1Die4YwmW3f5U" \
"1tqmg=, manifest: [ xl4_pkg_update_manifest, [ package, GW-ECU-36" \
"10820-DB03-0x005B ], [ name, PSCU ], [ type, \\/GW\\/ECU\\/3610820-D" \
"B03 ], [ version, 3610823-DB031006 ], [ hardware-statement, 'make" \
":FAW' AND 'model:C229' AND 'year:2020' AND 'partNumber:3610820-DB" \
"03' ], [ rollback, [ user-agent-controlled, true ] ], [ empty, fa" \
"lse ], [ delta-reference, 3610823-DB031006 ], [ ign-mode, ON ], [" \
" ign-timeout, 120 ], [ ecuid, 0x005B ] ], length: 57899 } }, roll" \
"back-versions: [ 3610823-DB031002 ], terminal-failure: false, upd" \
"ate-status: 90, expiration: 2020-06-19T00:00:00.000Z, update-prog" \
"ress: { }, download-consent: { state: 3 } } } ], policies: [ { ty" \
"pe: fontana:vehicle_speed, kmph: 0 }, { type: fontana:engine_spee" \
"d, rpm: 0 }, { type: TIME_WINDOW, source: user }, { type: fontana" \
":start_stop_not_running }, { type: SINGLE_USE_CAMPAIGN }, { type:" \
" fontana:parked }, { type: fontana:upgrade_time, seconds: 240, co" \
"mputed-seconds: 240 }, { type: fontana:epb_locked }, { type: font" \
"ana:power_state_of_charge, percentage: 20 } ], executing: false, " \
"policy-satisfaction: { } }, { id: 1216, release-notes: {\"version\"" \
":2,\"title\":{\"en\":\"LCDAL-2-1\",\"zh\":\"LCDAL-2-1\"},\"info\":{\"zh\":\"成功\"}" \
"}, targets: [ { package: { name: GW-ECU-3616325-DB03-0x0076, type" \
": \\/GW\\/ECU\\/3616325-DB03, version: 2001, current-version: 2001, " \
"version-list: { 2001: { downloaded: true, file: \\/fota\\/download\\" \
"/GW-ECU-3616325-DB03-0x0076-2001.x, sha-256: Xw8zetqLTGpzCiqq4Byb" \
"BiYvc9NYv\\/YO4iwBxYqsdGc=, manifest: [ xl4_pkg_update_manifest, [" \
" package, GW-ECU-3616325-DB03-0x0076 ], [ name, LCDA1 ], [ type, " \
"\\/GW\\/ECU\\/3616325-DB03 ], [ version, 2001 ], [ hardware-statemen" \
"t, 'make:FAW' AND 'model:C229' AND 'year:2020' AND 'partNumber:36" \
"16325-DB03' ], [ rollback, [ user-agent-controlled, true ] ], [ e" \
"mpty, false ], [ delta-reference, 2001 ], [ ign-mode, ON ], [ ign" \
"-timeout, 120 ], [ ecuid, 0x0076 ] ], length: 320212 } }, rollbac" \
"k-versions: [ 2002 ], terminal-failure: false, update-status: 90," \
" expiration: 2020-06-18T00:00:00.000Z, update-progress: { }, down" \
"load-consent: { state: 3 } } } ], policies: [ { type: fontana:veh" \
"icle_speed, kmph: 0 }, { type: fontana:engine_speed, rpm: 0 }, { " \
"type: TIME_WINDOW, source: user }, { type: fontana:start_stop_not" \
"_running }, { type: SINGLE_USE_CAMPAIGN }, { type: fontana:parked" \
" }, { type: fontana:upgrade_time, seconds: 240, computed-seconds:" \
" 240 }, { type: fontana:epb_locked }, { type: fontana:power_state" \
"_of_charge, percentage: 20 } ], executing: false, policy-satisfac" \
"tion: { } } ], non-campaigns: [ { name: GW-ECU-3614115-DB31-0x004" \
"8, current-version: SW0200200410, terminal-failure: false, update" \
"-status: 10, update-progress: { }, download-consent: { state: 3 }" \
" }, { name: GW-ECU-3610320-DB01-0x0057, current-version: 3610812-" \
"DB012003, terminal-failure: false, update-status: 10, update-prog" \
"ress: { }, download-consent: { state: 3 } }, { name: GW-ECU-36100" \
"90-DB03-0x005C, current-version: 3610831-DB033001, terminal-failu" \
"re: false, update-status: 10, update-progress: { }, download-cons" \
"ent: { state: 3 } }, { name: GW-ECU-3616215-DB31-0x0074, current-" \
"version: 2001, terminal-failure: false, update-status: 10, update" \
"-progress: { }, download-consent: { state: 3 } }, { name: GW-ECU-" \
"3610015-DB01-0x0051, current-version: 3610015-DB012144, terminal-" \
"failure: false, update-status: 10, update-progress: { }, download" \
"-consent: { state: 3 } }, { name: GW-ECU-3785110-DB05-0x0073, cur" \
"rent-version: SW:V3.2, terminal-failure: false, update-status: 10" \
", update-progress: { }, download-consent: { state: 3 } }, { name:" \
" GW-ECU-3616215-DB03-0x0074, current-version: 2001, terminal-fail" \
"ure: false, update-status: 10, update-progress: { }, download-con" \
"sent: { state: 3 } }, { name: GW-ECU-3710085-DB01-0x005E, current" \
"-version: BV07, terminal-failure: false, update-status: 10, updat" \
"e-progress: { }, download-consent: { state: 3 } }, { name: GW-ECU" \
"-3611015-DB31-0x0032, current-version: FDCT400DB31H6061, terminal" \
"-failure: false, update-status: 10, update-progress: { }, downloa" \
"d-consent: { state: 3 } }, { name: GW-3630015-DB01-0x0000, curren" \
"t-version: 3630801-DB014000, terminal-failure: false, update-stat" \
"us: 10, update-progress: { }, download-consent: { state: 3 } }, {" \
" name: GW-3630015-DB31-0x0000, current-version: 3630801-DB314000," \
" terminal-failure: false, update-status: 10, update-progress: { }" \
", download-consent: { state: 3 } }, { name: GW-ECU-3610330-DB01-0" \
"x0059, current-version: 3610814-DB012003, terminal-failure: false" \
", update-status: 10, update-progress: { }, download-consent: { st" \
"ate: 3 } }, { name: GW-ECU-3629310-DB05-0x007B, current-version: " \
"3002            , terminal-failure: false, update-status: 10, upd" \
"ate-progress: { }, download-consent: { state: 3 } }, { name: GW-E" \
"CU-3616330-DB03-0x0077, current-version: 2001            , termin" \
"al-failure: false, update-status: 10, update-progress: { }, downl" \
"oad-consent: { state: 3 } }, { name: GW-ECU-3611015-DB01-0x0032, " \
"current-version: FDCT400DB31H6061, terminal-failure: false, updat" \
"e-status: 10, update-progress: { }, download-consent: { state: 3 " \
"} }, { name: GW-ECU-3748030-DB03-0x005D, current-version: 3748802" \
"-DB053002, terminal-failure: false, update-status: 10, update-pro" \
"gress: { }, download-consent: { state: 3 } }, { name: GW-ECU-3550" \
"020-DB01-0x0041, current-version: BB99860, terminal-failure: fals" \
"e, update-status: 10, update-progress: { }, download-consent: { s" \
"tate: 3 } }, { name: GW-ECU-3630030-DB31-0x0049, current-version:" \
" SW:B.0.4.9, terminal-failure: false, update-status: 10, update-p" \
"rogress: { }, download-consent: { state: 3 } }, { name: GW-ECU-81" \
"12025-DB01-0x0055, current-version: 2000            , terminal-fa" \
"ilure: false, update-status: 10, update-progress: { }, download-c" \
"onsent: { state: 3 } }, { name: GW-ECU-3711030-DB03-0x007A, curre" \
"nt-version: SV1.4, terminal-failure: false, update-status: 10, up" \
"date-progress: { }, download-consent: { state: 3 } }, { name: GW-" \
"ECU-3624115-DB01-0x0045, current-version: 3624811-DB014039, termi" \
"nal-failure: false, update-status: 10, update-progress: { }, down" \
"load-consent: { state: 3 } }, { name: GW-ECU-3785110-DB01-0x0073," \
" current-version: SW:V3.2, terminal-failure: false, update-status" \
": 10, update-progress: { }, download-consent: { state: 3 } }, { n" \
"ame: GW-ECU-3610755-DB03-0x005A, current-version: 3610817-DB03100" \
"8, terminal-failure: false, update-status: 10, update-progress: {" \
" }, download-consent: { state: 3 } }, { name: GW-ECU-3785250-DB05" \
"-0x0072, current-version: 3002            , terminal-failure: fal" \
"se, update-status: 10, update-progress: { }, download-consent: { " \
"state: 3 } } ] }, reply-to: 268249633 }" \
"c0aa070 { type: FCT_BUS_MESSAGE_QUERY_UPDATE_RESPONSE, body: { campaigns: [ { id: 123" \
"9, release-notes: {\"version\":2,\"title\":{\"en\":\"DDCU1-2\",\"zh\":\"DDCU" \
"1-2\"},\"info\":{\"zh\":\"请等待\"}}, targets: [ { package: { name: GW-ECU-" \
"3610315-DB01-0x0056, type: \\/GW\\/ECU\\/3610315-DB01, version: 3610" \
"811-DB012003, current-version: 3610811-DB012003, version-list: { " \
"3610811-DB012003: { downloaded: true, file: \\/fota\\/download\\/GW-" \
"ECU-3610315-DB01-0x0056-3610811-DB012003.x, sha-256: VTmtgLu1MWYn" \
"3rb7k7EsxvXnBHSTAsScfa2Qz3LdC\\/c=, manifest: [ xl4_pkg_update_man" \
"ifest, [ package, GW-ECU-3610315-DB01-0x0056 ], [ name, DDCU ], [" \
" type, \\/GW\\/ECU\\/3610315-DB01 ], [ version, 3610811-DB012003 ], " \
"[ hardware-statement, 'make:FAW' AND 'model:C229' AND 'year:2020'" \
" AND 'partNumber:3610315-DB01' ], [ rollback, [ user-agent-contro" \
"lled, true ] ], [ empty, false ], [ delta-reference, 3610811-DB01" \
"2003 ], [ ign-mode, ON ], [ ign-timeout, 120 ], [ ecuid, 0x0056 ]" \
" ], length: 88255 } }, rollback-versions: [ 3610811-DB012001 ], t" \
"erminal-failure: false, update-status: 90, expiration: 2020-06-20" \
"T00:00:00.000Z, update-progress: { }, download-consent: { state: " \
"3 } } } ], policies: [ { type: fontana:vehicle_speed, kmph: 0 }, " \
"{ type: fontana:engine_speed, rpm: 0 }, { type: TIME_WINDOW, sour" \
"ce: user }, { type: fontana:start_stop_not_running }, { type: SIN" \
"GLE_USE_CAMPAIGN }, { type: fontana:parked }, { type: fontana:upg" \
"rade_time, seconds: 240, computed-seconds: 240 }, { type: fontana" \
":epb_locked }, { type: fontana:power_state_of_charge, percentage:" \
" 20 } ], executing: false, policy-satisfaction: { } }, { id: 1339" \
", release-notes: {\"version\":2,\"title\":{\"en\":\"SCM_1\",\"zh\":\"SCM_1\"}" \
",\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}}, targets: [ { package:" \
" { name: GW-ECU-3610350-DB01-0x0053, type: \\/GW\\/ECU\\/3610350-DB0" \
"1, version: 3610816-DB011003, current-version: 3610816-DB011003, " \
"version-list: { 3610816-DB011003: { downloaded: true, file: \\/fot" \
"a\\/download\\/GW-ECU-3610350-DB01-0x0053-3610816-DB011003.x, sha-2" \
"56: an4W6vX916xuHLVFAGLvLrRHR4eB0GafNUx5HRP864k=, manifest: [ xl4" \
"_pkg_update_manifest, [ package, GW-ECU-3610350-DB01-0x0053 ], [ " \
"name, SCM ], [ type, \\/GW\\/ECU\\/3610350-DB01 ], [ version, 361081" \
"6-DB011003 ], [ hardware-statement, 'make:FAW' AND 'model:C229' A" \
"ND 'year:2020' AND 'partNumber:3610350-DB01' ], [ rollback, [ use" \
"r-agent-controlled, true ] ], [ empty, false ], [ delta-reference" \
", 3610816-DB011003 ], [ ign-mode, ON ], [ ign-timeout, 120 ], [ e" \
"cuid, 0x0053 ] ], length: 35650 } }, rollback-versions: [ 3610816" \
"-DB011004 ], terminal-failure: false, update-status: 90, expirati" \
"on: 2020-07-02T00:00:00.000Z, update-progress: { }, download-cons" \
"ent: { state: 3 } } } ], policies: [ { type: fontana:vehicle_spee" \
"d, kmph: 0 }, { type: fontana:engine_speed, rpm: 0 }, { type: TIM" \
"E_WINDOW, source: user }, { type: fontana:start_stop_not_running " \
"}, { type: SINGLE_USE_CAMPAIGN }, { type: fontana:parked }, { typ" \
"e: fontana:upgrade_time, seconds: 240, computed-seconds: 240 }, {" \
" type: fontana:epb_locked }, { type: fontana:power_state_of_charg" \
"e, percentage: 20 } ], executing: false, policy-satisfaction: { }" \
" }, { id: 1350, release-notes: {\"version\":2,\"title\":{\"en\":\"TBOX_4" \
"00X\",\"zh\":\"TBOX_400X\"},\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}}," \
" targets: [ { package: { name: GW-ECU-7905070-DB01-0x0010, type: " \
"\\/GW\\/ECU\\/7905070-DB01, version: 7905801-DB01400X, current-versi" \
"on: 7905801-DB01400X, version-list: { 7905801-DB01400X: { downloa" \
"ded: true, file: \\/fota\\/download\\/GW-ECU-7905070-DB01-0x0010-790" \
"5801-DB01400X.x, sha-256: fMb73ZJiqKyOq4G3mFcATJgVlM4g5icai5maxQH" \
"nKyI=, manifest: [ xl4_pkg_update_manifest, [ package, GW-ECU-790" \
"5070-DB01-0x0010 ], [ name, TBOX ], [ type, \\/GW\\/ECU\\/7905070-DB" \
"01 ], [ version, 7905801-DB01400X ], [ hardware-statement, 'make:" \
"FAW' AND 'model:C229' AND 'year:2020' AND 'partNumber:7905070-DB0" \
"1' ], [ rollback, [ user-agent-controlled, true ] ], [ empty, fal" \
"se ], [ delta-reference, 7905801-DB01400X ], [ ign-mode, ON ], [ " \
"ign-timeout, 600 ], [ ecuid, 0x0010 ] ], length: 95681863 } }, ro" \
"llback-versions: [ 7905801-DB014002 ], terminal-failure: false, u" \
"pdate-status: 90, expiration: 2020-07-04T00:00:00.000Z, update-pr" \
"ogress: { }, download-consent: { state: 0, expiration: 2020-07-04" \
"T07:43:30.000Z } } } ], policies: [ { type: fontana:vehicle_speed" \
", kmph: 0 }, { type: fontana:engine_speed, rpm: 0 }, { type: TIME" \
"_WINDOW, source: user }, { type: fontana:start_stop_not_running }" \
", { type: SINGLE_USE_CAMPAIGN }, { type: fontana:parked }, { type" \
": fontana:upgrade_time, seconds: 1200, computed-seconds: 1200 }, " \
"{ type: fontana:epb_locked }, { type: fontana:power_state_of_char" \
"ge, percentage: 20 } ], executing: false, policy-satisfaction: { " \
"} }, { id: 1323, release-notes: {\"version\":2,\"title\":{\"en\":\"DSCU_" \
"1\",\"zh\":\"DSCU_1\"},\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}}, targ" \
"ets: [ { package: { name: GW-ECU-3610815-DB03-0x0054, type: \\/GW\\" \
"/ECU\\/3610815-DB03, version: 3610822-DB033002, current-version: 3" \
"610822-DB033002, version-list: { 3610822-DB033002: { downloaded: " \
"true, file: \\/fota\\/download\\/GW-ECU-3610815-DB03-0x0054-3610822-" \
"DB033002.x, sha-256: hdPaIyt9q79IHwHLt30pSNnlehgRuAc6r\\/rOYm06S9M" \
"=, manifest: [ xl4_pkg_update_manifest, [ package, GW-ECU-3610815" \
"-DB03-0x0054 ], [ name, DSCU ], [ type, \\/GW\\/ECU\\/3610815-DB03 ]" \
", [ version, 3610822-DB033002 ], [ hardware-statement, 'make:FAW'" \
" AND 'model:C229' AND 'year:2020' AND 'partNumber:3610815-DB03' ]" \
", [ rollback, [ user-agent-controlled, true ] ], [ empty, false ]" \
", [ delta-reference, 3610822-DB033002 ], [ ign-mode, ON ], [ ign-" \
"timeout, 120 ], [ ecuid, 0x0054 ] ], length: 55220 } }, rollback-" \
"versions: [ 3610822-DB031007 ], terminal-failure: false, update-s" \
"tatus: 90, expiration: 2020-07-01T00:00:00.000Z, update-progress:" \
" { }, download-consent: { state: 3 } } } ], policies: [ { type: f" \
"ontana:vehicle_speed, kmph: 0 }, { type: fontana:engine_speed, rp" \
"m: 0 }, { type: TIME_WINDOW, source: user }, { type: fontana:star" \
"t_stop_not_running }, { type: SINGLE_USE_CAMPAIGN }, { type: font" \
"ana:parked }, { type: fontana:upgrade_time, seconds: 240, compute" \
"d-seconds: 240 }, { type: fontana:epb_locked }, { type: fontana:p" \
"ower_state_of_charge, percentage: 20 } ], executing: false, polic" \
"y-satisfaction: { } }, { id: 1346, release-notes: {\"version\":2,\"t" \
"itle\":{\"en\":\"ACM_2\",\"zh\":\"ACM_2\"},\"info\":{\"en\":\"updating\",\"zh\":\"u" \
"pdating\"}}, targets: [ { package: { name: GW-ECU-3627015-DB01-0x0" \
"034, type: \\/GW\\/ECU\\/3627015-DB01, version: KA.ACM.16, current-v" \
"ersion: KA.ACM.16, version-list: { KA.ACM.16: { downloaded: true," \
" file: \\/fota\\/download\\/GW-ECU-3627015-DB01-0x0034-KA.ACM.16.x, " \
"sha-256: zPJBcf1YKAHtPXFsyGVPGbGi7vLeS9SQUwoZk3ysjs4=, manifest: " \
"[ xl4_pkg_update_manifest, [ package, GW-ECU-3627015-DB01-0x0034 " \
"], [ name, ACM ], [ type, \\/GW\\/ECU\\/3627015-DB01 ], [ version, K" \
"A.ACM.16 ], [ hardware-statement, 'make:FAW' AND 'model:C229' AND" \
" 'year:2020' AND 'partNumber:3627015-DB01' ], [ rollback, [ user-" \
"agent-controlled, true ] ], [ empty, false ], [ delta-reference, " \
"KA.ACM.16 ], [ ign-mode, ON ], [ ign-timeout, 120 ], [ ecuid, 0x0" \
"034 ] ], length: 43459 } }, rollback-versions: [ KA.ACM.15 ], ter" \
"minal-failure: false, update-status: 90, expiration: 2020-07-04T0" \
"0:00:00.000Z, update-progress: { }, download-consent: { state: 0," \
" expiration: 2020-07-04T01:40:36.000Z } } } ], policies: [ { type" \
": fontana:vehicle_speed, kmph: 0 }, { type: fontana:engine_speed," \
" rpm: 0 }, { type: TIME_WINDOW, source: user }, { type: fontana:s" \
"tart_stop_not_running }, { type: SINGLE_USE_CAMPAIGN }, { type: f" \
"ontana:parked }, { type: fontana:upgrade_time, seconds: 240, comp" \
"uted-seconds: 240 }, { type: fontana:epb_locked }, { type: fontan" \
"a:power_state_of_charge, percentage: 20 } ], executing: false, po" \
"licy-satisfaction: { } }, { id: 1227, release-notes: {\"version\":2" \
",\"title\":{\"en\":\"HUD-2-1\",\"zh\":\"HUD-2-1\"},\"info\":{\"zh\":\"升级任务\"}}, t" \
"argets: [ { package: { name: GW-ECU-3830010-DB05-0x0061, type: \\/" \
"GW\\/ECU\\/3830010-DB05, version: MV1.1CV1.1, current-version: MV1." \
"0CV1.1, version-list: { MV1.1CV1.1: { downloaded: false, sha-256:" \
" Djj3kZif0tjE\\/cspaxBGDs1VkhYF14tWWniYeSAZFic=, manifest: [ xl4_p" \
"kg_update_manifest, [ package, GW-ECU-3830010-DB05-0x0061 ], [ na" \
"me, HUD ], [ type, \\/GW\\/ECU\\/3830010-DB05 ], [ version, MV1.1CV1" \
".1 ], [ hardware-statement, 'make:FAW' AND 'model:C229' AND 'year" \
":2020' AND 'partNumber:3830010-DB05' ], [ rollback, [ user-agent-" \
"controlled, true ] ], [ empty, false ], [ delta-reference, MV1.1C" \
"V1.1 ], [ ign-mode, ON ], [ ign-timeout, 360 ], [ ecuid, 0x0061 ]" \
" ], length: 465443 } }, rollback-version: MV1.0CV8.8, rollback-ve" \
"rsions: [ MV1.0CV8.8 ], terminal-failure: true, update-status: 40" \
", expiration: 2020-06-19T00:00:00.000Z, update-progress: { }, dow" \
"nload-consent: { state: 3 } } } ], policies: [ { type: fontana:ve" \
"hicle_speed, kmph: 0 }, { type: fontana:engine_speed, rpm: 0 }, {" \
" type: TIME_WINDOW, source: user }, { type: fontana:start_stop_no" \
"t_running }, { type: SINGLE_USE_CAMPAIGN }, { type: fontana:parke" \
"d }, { type: fontana:upgrade_time, seconds: 720, computed-seconds" \
": 720 }, { type: fontana:epb_locked }, { type: fontana:power_stat" \
"e_of_charge, percentage: 20 } ], executing: false, policy-satisfa" \
"ction: { } }, { id: 1327, release-notes: {\"version\":2,\"title\":{\"e" \
"n\":\"ACU_2\",\"zh\":\"ACU_2\"},\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}" \
"}, targets: [ { package: { name: GW-ECU-3607115-DB01-0x0035, type" \
": \\/GW\\/ECU\\/3607115-DB01, version: 3607801-DB012002, current-ver" \
"sion: 3607801-DB012002, version-list: { 3607801-DB012002: { downl" \
"oaded: true, file: \\/fota\\/download\\/GW-ECU-3607115-DB01-0x0035-3" \
"607801-DB012002.x, sha-256: DYxKSJ2B7itWEqLemlI12\\/uUqifjxSWtesYk" \
"NRr8HG8=, manifest: [ xl4_pkg_update_manifest, [ package, GW-ECU-" \
"3607115-DB01-0x0035 ], [ name, ACU ], [ type, \\/GW\\/ECU\\/3607115-" \
"DB01 ], [ version, 3607801-DB012002 ], [ hardware-statement, 'mak" \
"e:FAW' AND 'model:C229' AND 'year:2020' AND 'partNumber:3607115-D" \
"B01' ], [ rollback, [ user-agent-controlled, true ] ], [ empty, f" \
"alse ], [ delta-reference, 3607801-DB012002 ], [ ign-mode, ON ], " \
"[ ign-timeout, 180 ], [ ecuid, 0x0035 ] ], length: 173253 } }, ro" \
"llback-versions: [ 3607801-DB013001 ], terminal-failure: false, u" \
"pdate-status: 90, expiration: 2020-07-01T00:00:00.000Z, update-pr" \
"ogress: { }, download-consent: { state: 3 } } } ], policies: [ { " \
"type: fontana:vehicle_speed, kmph: 0 }, { type: fontana:engine_sp" \
"eed, rpm: 0 }, { type: TIME_WINDOW, source: user }, { type: fonta" \
"na:start_stop_not_running }, { type: SINGLE_USE_CAMPAIGN }, { typ" \
"e: fontana:parked }, { type: fontana:upgrade_time, seconds: 360, " \
"computed-seconds: 360 }, { type: fontana:epb_locked }, { type: fo" \
"ntana:power_state_of_charge, percentage: 20 } ], executing: false" \
", policy-satisfaction: { } }, { id: 1240, release-notes: {\"versio" \
"n\":2,\"title\":{\"en\":\"ADB11-2\",\"zh\":\"ADB11-2\"},\"info\":{\"zh\":\"成功了\"}}" \
", targets: [ { package: { name: GW-ECU-3711025-DB03-0x0079, type:" \
" \\/GW\\/ECU\\/3711025-DB03, version: SV1.4, current-version: SV1.4," \
" version-list: { SV1.4: { downloaded: true, file: \\/fota\\/downloa" \
"d\\/GW-ECU-3711025-DB03-0x0079-SV1.4.x, sha-256: d9oBYuCFrML0drr2F" \
"K06TYUWIxhVfJ\\/aLRRKb8OfORY=, manifest: [ xl4_pkg_update_manifest" \
", [ package, GW-ECU-3711025-DB03-0x0079 ], [ name, ADBL ], [ type" \
", \\/GW\\/ECU\\/3711025-DB03 ], [ version, SV1.4 ], [ hardware-state" \
"ment, 'make:FAW' AND 'model:C229' AND 'year:2020' AND 'partNumber" \
":3711025-DB03' ], [ rollback, [ user-agent-controlled, true ] ], " \
"[ empty, false ], [ delta-reference, SV1.4 ], [ ign-mode, ON ], [" \
" ign-timeout, 120 ], [ ecuid, 0x0079 ] ], length: 52430 } }, roll" \
"back-versions: [ SV1.3 ], terminal-failure: false, update-status:" \
" 90, expiration: 2020-06-20T00:00:00.000Z, update-progress: { }, " \
"download-consent: { state: 3 } } } ], policies: [ { type: fontana" \
":vehicle_speed, kmph: 0 }, { type: fontana:engine_speed, rpm: 0 }" \
", { type: TIME_WINDOW, source: user }, { type: fontana:start_stop" \
"_not_running }, { type: SINGLE_USE_CAMPAIGN }, { type: fontana:pa" \
"rked }, { type: fontana:upgrade_time, seconds: 240, computed-seco" \
"nds: 240 }, { type: fontana:epb_locked }, { type: fontana:power_s" \
"tate_of_charge, percentage: 20 } ], executing: false, policy-sati" \
"sfaction: { } }, { id: 1254, release-notes: {\"version\":2,\"title\":" \
"{\"en\":\"5包升级-预约\",\"zh\":\"5包升级-预约\"},\"info\":{\"en\":\"5包升级-预约\",\"zh\":\"5包升级" \
"-预约\"}}, targets: [ { package: { name: GW-ECU-3629100-DB01-0x0071," \
" type: \\/GW\\/ECU\\/3629100-DB01, version: SW0204200526, current-ve" \
"rsion: SW0204200526, version-list: { SW0204200526: { downloaded: " \
"true, sha-256: mqMfZudI0F9BimPyFLkCF5vJL\\/kAAWeFT+ebk3ix7lw=, man" \
"ifest: [ xl4_pkg_update_manifest, [ package, GW-ECU-3629100-DB01-" \
"0x0071 ], [ name, ADV ], [ type, \\/GW\\/ECU\\/3629100-DB01 ], [ ver" \
"sion, SW0204200526 ], [ hardware-statement, 'make:FAW' AND 'model" \
":C229' AND 'year:2020' AND 'partNumber:3629100-DB01' ], [ rollbac" \
"k, [ user-agent-controlled, true ] ], [ empty, false ], [ delta-r" \
"eference, SW0204200526 ], [ ign-mode, ON ], [ ign-timeout, 300 ]," \
" [ ecuid, 0x0071 ] ], length: 0 } }, rollback-versions: [ SW02042" \
"00526 ], terminal-failure: false, update-status: 90, expiration: " \
"2020-06-29T00:00:00.000Z, update-progress: { }, download-consent:" \
" { state: 1 } } }, { package: { name: GW-ECU-3710060-DB01-0x00F0," \
" type: \\/GW\\/ECU\\/3710060-DB01, version: 3710060-DB010005, curren" \
"t-version: 3710060-DB010005, version-list: { 3710060-DB010005: { " \
"downloaded: true, sha-256: Hcm0bk5bi+5yf7wXWBtvrMtnZeTI7fjhb5g\\/n" \
"E67\\/pw=, manifest: [ xl4_pkg_update_manifest, [ package, GW-ECU-" \
"3710060-DB01-0x00F0 ], [ name, ALU ], [ type, \\/GW\\/ECU\\/3710060-" \
"DB01 ], [ version, 3710060-DB010005 ], [ hardware-statement, 'mak" \
"e:FAW' AND 'model:C229' AND 'year:2020' AND 'partNumber:3710060-D" \
"B01' ], [ rollback, [ user-agent-controlled, true ] ], [ empty, f" \
"alse ], [ delta-reference, 3710060-DB010005 ], [ ign-mode, ON ], " \
"[ ign-timeout, 120 ], [ ecuid, 0x00F0 ] ], length: 0 } }, rollbac" \
"k-versions: [ 3710060-DB010005 ], terminal-failure: false, update" \
"-status: 90, expiration: 2020-06-29T00:00:00.000Z, update-progres" \
"s: { }, download-consent: { state: 1 } } }, { package: { name: GW" \
"-ECU-3830015-DB05-0x0064, type: \\/GW\\/ECU\\/3830015-DB05, version:" \
" 1031000000000000, current-version: 1031000000000000, version-lis" \
"t: { 1031000000000000: { downloaded: true, file: \\/fota\\/download" \
"\\/GW-ECU-3830015-DB05-0x0064-1031000000000000.x, sha-256: 7ahKy29" \
"2lYBixG3ly8JIA9SFvyrteLFRruXjxU+rXCU=, manifest: [ xl4_pkg_update" \
"_manifest, [ package, GW-ECU-3830015-DB05-0x0064 ], [ name, FDM ]" \
", [ type, \\/GW\\/ECU\\/3830015-DB05 ], [ version, 1031000000000000 " \
"], [ hardware-statement, 'make:FAW' AND 'model:C229' AND 'year:20" \
"20' AND 'partNumber:3830015-DB05' ], [ rollback, [ user-agent-con" \
"trolled, true ] ], [ empty, false ], [ delta-reference, 103100000" \
"0000000 ], [ ign-mode, ON ], [ ign-timeout, 120 ], [ ecuid, 0x006" \
"4 ] ], length: 78392 } }, rollback-versions: [ 1030             ]" \
", terminal-failure: false, update-status: 90, expiration: 2020-06" \
"-29T00:00:00.000Z, update-progress: { }, download-consent: { stat" \
"e: 3 } } }, { package: { name: GW-ECU-1504270-DB01-0x0033, type: " \
"\\/GW\\/ECU\\/1504270-DB01, version: KA.EGSM.06, current-version: KA" \
".EGSM.02      , version-list: { KA.EGSM.06: { downloaded: false, " \
"sha-256: eWPNWozH4UmxEbMOASzKDD3yZS8R3vSshJ6gzoLyw3I=, manifest: " \
"[ xl4_pkg_update_manifest, [ package, GW-ECU-1504270-DB01-0x0033 " \
"], [ name, EGSM ], [ type, \\/GW\\/ECU\\/1504270-DB01 ], [ version, " \
"KA.EGSM.06 ], [ hardware-statement, 'make:FAW' AND 'model:C229' A" \
"ND 'year:2020' AND 'partNumber:1504270-DB01' ], [ rollback, [ use" \
"r-agent-controlled, true ] ], [ empty, false ], [ delta-reference" \
", KA.EGSM.06 ], [ ign-mode, ON ], [ ign-timeout, 120 ], [ ecuid, " \
"0x0033 ] ], length: 28588 } }, rollback-versions: [ KA.EGSM.04 ]," \
" terminal-failure: false, update-status: 80, expiration: 2020-06-" \
"29T00:00:00.000Z, update-progress: { }, download-consent: { state" \
": 3 } } } ], policies: [ { type: fontana:vehicle_speed, kmph: 0 }" \
", { type: fontana:engine_speed, rpm: 0 }, { type: TIME_WINDOW, so" \
"urce: user }, { type: fontana:start_stop_not_running }, { type: S" \
"INGLE_USE_CAMPAIGN }, { type: fontana:parked }, { type: fontana:u" \
"pgrade_time, seconds: 2040, computed-seconds: 2040 }, { type: fon" \
"tana:epb_locked }, { type: fontana:power_state_of_charge, percent" \
"age: 20 } ], executing: false, policy-satisfaction: { } }, { id: " \
"1320, release-notes: {\"version\":2,\"title\":{\"en\":\"RLDCU_2\",\"zh\":\"R" \
"LDCU_2\"},\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}}, targets: [ { " \
"package: { name: GW-ECU-3610325-DB01-0x0058, type: \\/GW\\/ECU\\/361" \
"0325-DB01, version: 3610813-DB012003, current-version: NULL, vers" \
"ion-list: { 3610813-DB012003: { downloaded: false, sha-256: KBvxF" \
"1ITFpM2Vqu3U+DLC9J3tLlWdv5mYI4261Khsro=, manifest: [ xl4_pkg_upda" \
"te_manifest, [ package, GW-ECU-3610325-DB01-0x0058 ], [ name, RLD" \
"CU ], [ type, \\/GW\\/ECU\\/3610325-DB01 ], [ version, 3610813-DB012" \
"003 ], [ hardware-statement, 'make:FAW' AND 'model:C229' AND 'yea" \
"r:2020' AND 'partNumber:3610325-DB01' ], [ rollback, [ user-agent" \
"-controlled, true ] ], [ empty, false ], [ delta-reference, 36108" \
"13-DB012003 ], [ ign-mode, ON ], [ ign-timeout, 120 ], [ ecuid, 0" \
"x0058 ] ], length: 95299 } }, rollback-version: NULL, rollback-ve" \
"rsions: [ NULL ], terminal-failure: false, update-status: 100, ex" \
"piration: 2020-07-01T00:00:00.000Z, update-progress: { }, downloa" \
"d-consent: { state: 3 } } } ], policies: [ { type: fontana:vehicl" \
"e_speed, kmph: 0 }, { type: fontana:engine_speed, rpm: 0 }, { typ" \
"e: TIME_WINDOW, source: user }, { type: fontana:start_stop_not_ru" \
"nning }, { type: SINGLE_USE_CAMPAIGN }, { type: fontana:parked }," \
" { type: fontana:upgrade_time, seconds: 240, computed-seconds: 24" \
"0 }, { type: fontana:epb_locked }, { type: fontana:power_state_of" \
"_charge, percentage: 20 } ], executing: false, policy-satisfactio" \
"n: { } }, { id: 1220, release-notes: {\"version\":2,\"title\":{\"en\":\"" \
"RLCU-1-2\",\"zh\":\"RLCU-1-2\"},\"info\":{\"zh\":\"成功\"}}, targets: [ { pack" \
"age: { name: GW-ECU-3710095-DB01-0x005F, type: \\/GW\\/ECU\\/3710095" \
"-DB01, version: BV06-1, current-version: BV06-1, version-list: { " \
"BV06-1: { downloaded: true, file: \\/fota\\/download\\/GW-ECU-371009" \
"5-DB01-0x005F-BV06-1.x, sha-256: bXK8CnRdCG4ah3E88uLnowkf46nd6I5p" \
"sYbwHqAbg7w=, manifest: [ xl4_pkg_update_manifest, [ package, GW-" \
"ECU-3710095-DB01-0x005F ], [ name, RLCU ], [ type, \\/GW\\/ECU\\/371" \
"0095-DB01 ], [ version, BV06-1 ], [ hardware-statement, 'make:FAW" \
"' AND 'model:C229' AND 'year:2020' AND 'partNumber:3710095-DB01' " \
"], [ rollback, [ user-agent-controlled, true ] ], [ empty, false " \
"], [ delta-reference, BV06-1 ], [ ign-mode, ON ], [ ign-timeout, " \
"120 ], [ ecuid, 0x005F ] ], length: 40671 } }, rollback-versions:" \
" [ BV06 ], terminal-failure: false, update-status: 90, expiration" \
": 2020-06-18T00:00:00.000Z, update-progress: { }, download-consen" \
"t: { state: 3 } } } ], policies: [ { type: fontana:vehicle_speed," \
" kmph: 0 }, { type: fontana:engine_speed, rpm: 0 }, { type: TIME_" \
"WINDOW, source: user }, { type: fontana:start_stop_not_running }," \
" { type: SINGLE_USE_CAMPAIGN }, { type: fontana:parked }, { type:" \
" fontana:upgrade_time, seconds: 240, computed-seconds: 240 }, { t" \
"ype: fontana:epb_locked }, { type: fontana:power_state_of_charge," \
" percentage: 20 } ], executing: false, policy-satisfaction: { } }" \
", { id: 1314, release-notes: {\"version\":2,\"title\":{\"en\":\"IFC1\",\"z" \
"h\":\"IFC1\"},\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}}, targets: [ " \
"{ package: { name: GW-ECU-3616215-DB05-0x0074, type: \\/GW\\/ECU\\/3" \
"616215-DB05, version: 2001, current-version: 2001, version-list: " \
"{ 2001: { downloaded: true, file: \\/fota\\/download\\/GW-ECU-361621" \
"5-DB05-0x0074-2001.x, sha-256: ObYBuj8CPHriQeMkg1pzKaEZJ7SeVTteFk" \
"GEK4xWQqM=, manifest: [ xl4_pkg_update_manifest, [ package, GW-EC" \
"U-3616215-DB05-0x0074 ], [ name, IFC ], [ type, \\/GW\\/ECU\\/361621" \
"5-DB05 ], [ version, 2001 ], [ hardware-statement, 'make:FAW' AND" \
" 'model:C229' AND 'year:2020' AND 'partNumber:3616215-DB05' ], [ " \
"rollback, [ user-agent-controlled, true ] ], [ empty, false ], [ " \
"delta-reference, 2001 ], [ ign-mode, ON ], [ ign-timeout, 180 ], " \
"[ ecuid, 0x0074 ] ], length: 383749 } }, rollback-versions: [ 200" \
"2 ], terminal-failure: false, update-status: 90, expiration: 2020" \
"-07-01T00:00:00.000Z, update-progress: { }, download-consent: { s" \
"tate: 3 } } } ], policies: [ { type: fontana:vehicle_speed, kmph:" \
" 0 }, { type: fontana:engine_speed, rpm: 0 }, { type: TIME_WINDOW" \
", source: user }, { type: fontana:start_stop_not_running }, { typ" \
"e: SINGLE_USE_CAMPAIGN }, { type: fontana:parked }, { type: fonta" \
"na:upgrade_time, seconds: 360, computed-seconds: 360 }, { type: f" \
"ontana:epb_locked }, { type: fontana:power_state_of_charge, perce" \
"ntage: 20 } ], executing: false, policy-satisfaction: { } }, { id" \
": 1348, release-notes: {\"version\":2,\"title\":{\"en\":\"IVI1\",\"zh\":\"IV" \
"I1\"},\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}}, targets: [ { pack" \
"age: { name: GW-ECU-7901010-DB01-0x0020, type: \\/GW\\/ECU\\/7901010" \
"-DB01, version: C229IVI-02.00.00, current-version: C229IVI-02.00." \
"00, version-list: { C229IVI-02.00.00: { downloaded: true, file: \\" \
"/fota\\/download\\/GW-ECU-7901010-DB01-0x0020-C229IVI-02.00.00.x, s" \
"ha-256: DtJd6h\\/eVukiPWCpQCanCUchFgOYZMaPEvIH32nRlDo=, manifest: " \
"[ xl4_pkg_update_manifest, [ package, GW-ECU-7901010-DB01-0x0020 " \
"], [ name, IVI ], [ type, \\/GW\\/ECU\\/7901010-DB01 ], [ version, C" \
"229IVI-02.00.00 ], [ hardware-statement, 'make:FAW' AND 'model:C2" \
"29' AND 'year:2020' AND 'partNumber:7901010-DB01' ], [ rollback, " \
"[ user-agent-controlled, true ] ], [ empty, false ], [ delta-refe" \
"rence, C229IVI-02.00.00 ], [ ign-mode, ON ], [ ign-timeout, 1800 " \
"], [ ecuid, 0x0020 ] ], length: 1851703469 } }, rollback-versions" \
": [ C229IVI-01.09.03 ], terminal-failure: false, update-status: 9" \
"0, expiration: 2020-07-04T00:00:00.000Z, update-progress: { }, do" \
"wnload-consent: { state: 0, expiration: 2020-07-04T03:08:36.000Z " \
"} } } ], policies: [ { type: fontana:vehicle_speed, kmph: 0 }, { " \
"type: fontana:engine_speed, rpm: 0 }, { type: TIME_WINDOW, source" \
": user }, { type: fontana:start_stop_not_running }, { type: SINGL" \
"E_USE_CAMPAIGN }, { type: fontana:parked }, { type: fontana:upgra" \
"de_time, seconds: 3600, computed-seconds: 3600 }, { type: fontana" \
":epb_locked }, { type: fontana:power_state_of_charge, percentage:" \
" 20 } ], executing: false, policy-satisfaction: { } }, { id: 1354" \
", release-notes: {\"version\":2,\"title\":{\"en\":\"EPS_1\",\"zh\":\"EPS_1\"}" \
",\"info\":{\"en\":\"updating\",\"zh\":\"updating\"}}, targets: [ { package:" \
" { name: GW-ECU-3418310-DB01-0x0042, type: \\/GW\\/ECU\\/3418310-DB0" \
"1, version: 3418801-DB012006, current-version: 3418801-DB013008, " \
"version-list: { 3418801-DB012006: { downloaded: true, file: \\/fot" \
"a\\/download\\/GW-ECU-3418310-DB01-0x0042-3418801-DB012006.x, sha-2" \
"56: IbIaQjrxxqNUZJbPU1ZgNIxnwSxgP4Sogtnccf\\/7V9M=, manifest: [ xl" \
"4_pkg_update_manifest, [ package, GW-ECU-3418310-DB01-0x0042 ], [" \
" name, EPS ], [ type, \\/GW\\/ECU\\/3418310-DB01 ], [ version, 34188" \
"01-DB012006 ], [ hardware-statement, 'make:FAW' AND 'model:C229' " \
"AND 'year:2020' AND 'partNumber:3418310-DB01' ], [ rollback, [ us" \
"er-agent-controlled, true ] ], [ empty, false ], [ delta-referenc" \
"e, 3418801-DB012006 ], [ ign-mode, ON ], [ ign-timeout, 360 ], [ " \
"ecuid, 0x0042 ] ], length: 179349 } }, rollback-versions: [ 34188" \
"01-DB013008 ], terminal-failure: false, update-status: 50, expira" \
"tion: 2020-07-04T00:00:00.000Z, update-progress: { update-window:" \
" { } }, download-consent: { state: 0, expiration: 2020-07-04T08:2" \
"3:35.000Z } } } ], policies: [ { type: fontana:vehicle_speed, kmp" \
"h: 0 }, { type: fontana:engine_speed, rpm: 0 }, { type: TIME_WIND" \
"OW, source: user }, { type: fontana:start_stop_not_running }, { t" \
"ype: SINGLE_USE_CAMPAIGN }, { type: fontana:parked }, { type: fon" \
"tana:upgrade_time, seconds: 720, computed-seconds: 720 }, { type:" \
" fontana:epb_locked }, { type: fontana:power_state_of_charge, per" \
"centage: 20 } ], executing: true, policy-satisfaction: { download" \
": { reference: 125, response: [ ], satisfied: true, last-received" \
"-at: 2020-07-03T08:23:34.000Z } } }, { id: 1217, release-notes: {" \
"\"version\":2,\"title\":{\"en\":\"RMAR\",\"zh\":\"RMAR\"},\"info\":{\"zh\":\"升级\"}}" \
", targets: [ { package: { name: GW-ECU-3748030-DB05-0x005D, type:" \
" \\/GW\\/ECU\\/3748030-DB05, version: 3748802-DB323010, current-vers" \
"ion: 3748802-DB323010, version-list: { 3748802-DB323010: { downlo" \
"aded: true, file: \\/fota\\/download\\/GW-ECU-3748030-DB05-0x005D-37" \
"48802-DB323010.x, sha-256: JgDYTz6WCxStH7WzdzJoWclRcrCMeymztFYvp3" \
"t3Mp4=, manifest: [ xl4_pkg_update_manifest, [ package, GW-ECU-37" \
"48030-DB05-0x005D ], [ name, RMAR ], [ type, \\/GW\\/ECU\\/3748030-D" \
"B05 ], [ version, 3748802-DB323010 ], [ hardware-statement, 'make" \
":FAW' AND 'model:C229' AND 'year:2020' AND 'partNumber:3748030-DB" \
"05' ], [ rollback, [ user-agent-controlled, true ] ], [ empty, fa" \
"lse ], [ delta-reference, 3748802-DB323010 ], [ ign-mode, ON ], [" \
" ign-timeout, 180 ], [ ecuid, 0x005D ] ], length: 23084 } }, roll" \
"back-versions: [ 3748802-DB053002 ], terminal-failure: false, upd" \
"ate-status: 90, expiration: 2020-06-18T00:00:00.000Z, update-prog" \
"ress: { }, download-consent: { state: 3 } } } ], policies: [ { ty" \
"pe: fontana:vehicle_speed, kmph: 0 }, { type: fontana:engine_spee" \
"d, rpm: 0 }, { type: TIME_WINDOW, source: user }, { type: fontana" \
":start_stop_not_running }, { type: SINGLE_USE_CAMPAIGN }, { type:" \
" fontana:parked }, { type: fontana:upgrade_time, seconds: 360, co" \
"mputed-seconds: 360 }, { type: fontana:epb_locked }, { type: font" \
"ana:power_state_of_charge, percentage: 20 } ], executing: false, " \
"policy-satisfaction: { } }, { id: 1229, release-notes: {\"version\"" \
":2,\"title\":{\"en\":\"PSCU-1-2\",\"zh\":\"PSCU-1-2\"},\"info\":{\"zh\":\"请等待\"}}" \
", targets: [ { package: { name: GW-ECU-3610820-DB03-0x005B, type:" \
" \\/GW\\/ECU\\/3610820-DB03, version: 3610823-DB031006, current-vers" \
"ion: 3610823-DB031006, version-list: { 3610823-DB031006: { downlo" \
"aded: true, file: \\/fota\\/download\\/GW-ECU-3610820-DB03-0x005B-36" \
"10823-DB031006.x, sha-256: qVa78Z9yM+Uf+ytp2NZ3vTAtm1Die4YwmW3f5U" \
"1tqmg=, manifest: [ xl4_pkg_update_manifest, [ package, GW-ECU-36" \
"10820-DB03-0x005B ], [ name, PSCU ], [ type, \\/GW\\/ECU\\/3610820-D" \
"B03 ], [ version, 3610823-DB031006 ], [ hardware-statement, 'make" \
":FAW' AND 'model:C229' AND 'year:2020' AND 'partNumber:3610820-DB" \
"03' ], [ rollback, [ user-agent-controlled, true ] ], [ empty, fa" \
"lse ], [ delta-reference, 3610823-DB031006 ], [ ign-mode, ON ], [" \
" ign-timeout, 120 ], [ ecuid, 0x005B ] ], length: 57899 } }, roll" \
"back-versions: [ 3610823-DB031002 ], terminal-failure: false, upd" \
"ate-status: 90, expiration: 2020-06-19T00:00:00.000Z, update-prog" \
"ress: { }, download-consent: { state: 3 } } } ], policies: [ { ty" \
"pe: fontana:vehicle_speed, kmph: 0 }, { type: fontana:engine_spee" \
"d, rpm: 0 }, { type: TIME_WINDOW, source: user }, { type: fontana" \
":start_stop_not_running }, { type: SINGLE_USE_CAMPAIGN }, { type:" \
" fontana:parked }, { type: fontana:upgrade_time, seconds: 240, co" \
"mputed-seconds: 240 }, { type: fontana:epb_locked }, { type: font" \
"ana:power_state_of_charge, percentage: 20 } ], executing: false, " \
"policy-satisfaction: { } }, { id: 1216, release-notes: {\"version\"" \
":2,\"title\":{\"en\":\"LCDAL-2-1\",\"zh\":\"LCDAL-2-1\"},\"info\":{\"zh\":\"成功\"}" \
"}, targets: [ { package: { name: GW-ECU-3616325-DB03-0x0076, type" \
": \\/GW\\/ECU\\/3616325-DB03, version: 2001, current-version: 2001, " \
"version-list: { 2001: { downloaded: true, file: \\/fota\\/download\\" \
"/GW-ECU-3616325-DB03-0x0076-2001.x, sha-256: Xw8zetqLTGpzCiqq4Byb" \
"BiYvc9NYv\\/YO4iwBxYqsdGc=, manifest: [ xl4_pkg_update_manifest, [" \
" package, GW-ECU-3616325-DB03-0x0076 ], [ name, LCDA1 ], [ type, " \
"\\/GW\\/ECU\\/3616325-DB03 ], [ version, 2001 ], [ hardware-statemen" \
"t, 'make:FAW' AND 'model:C229' AND 'year:2020' AND 'partNumber:36" \
"16325-DB03' ], [ rollback, [ user-agent-controlled, true ] ], [ e" \
"mpty, false ], [ delta-reference, 2001 ], [ ign-mode, ON ], [ ign" \
"-timeout, 120 ], [ ecuid, 0x0076 ] ], length: 320212 } }, rollbac" \
"k-versions: [ 2002 ], terminal-failure: false, update-status: 90," \
" expiration: 2020-06-18T00:00:00.000Z, update-progress: { }, down" \
"load-consent: { state: 3 } } } ], policies: [ { type: fontana:veh" \
"icle_speed, kmph: 0 }, { type: fontana:engine_speed, rpm: 0 }, { " \
"type: TIME_WINDOW, source: user }, { type: fontana:start_stop_not" \
"_running }, { type: SINGLE_USE_CAMPAIGN }, { type: fontana:parked" \
" }, { type: fontana:upgrade_time, seconds: 240, computed-seconds:" \
" 240 }, { type: fontana:epb_locked }, { type: fontana:power_state" \
"_of_charge, percentage: 20 } ], executing: false, policy-satisfac" \
"tion: { } } ], non-campaigns: [ { name: GW-ECU-3614115-DB31-0x004" \
"8, current-version: SW0200200410, terminal-failure: false, update" \
"-status: 10, update-progress: { }, download-consent: { state: 3 }" \
" }, { name: GW-ECU-3610320-DB01-0x0057, current-version: 3610812-" \
"DB012003, terminal-failure: false, update-status: 10, update-prog" \
"ress: { }, download-consent: { state: 3 } }, { name: GW-ECU-36100" \
"90-DB03-0x005C, current-version: 3610831-DB033001, terminal-failu" \
"re: false, update-status: 10, update-progress: { }, download-cons" \
"ent: { state: 3 } }, { name: GW-ECU-3616215-DB31-0x0074, current-" \
"version: 2001, terminal-failure: false, update-status: 10, update" \
"-progress: { }, download-consent: { state: 3 } }, { name: GW-ECU-" \
"3610015-DB01-0x0051, current-version: 3610015-DB012144, terminal-" \
"failure: false, update-status: 10, update-progress: { }, download" \
"-consent: { state: 3 } }, { name: GW-ECU-3785110-DB05-0x0073, cur" \
"rent-version: SW:V3.2, terminal-failure: false, update-status: 10" \
", update-progress: { }, download-consent: { state: 3 } }, { name:" \
" GW-ECU-3616215-DB03-0x0074, current-version: 2001, terminal-fail" \
"ure: false, update-status: 10, update-progress: { }, download-con" \
"sent: { state: 3 } }, { name: GW-ECU-3710085-DB01-0x005E, current" \
"-version: BV07, terminal-failure: false, update-status: 10, updat" \
"e-progress: { }, download-consent: { state: 3 } }, { name: GW-ECU" \
"-3611015-DB31-0x0032, current-version: FDCT400DB31H6061, terminal" \
"-failure: false, update-status: 10, update-progress: { }, downloa" \
"d-consent: { state: 3 } }, { name: GW-3630015-DB01-0x0000, curren" \
"t-version: 3630801-DB014000, terminal-failure: false, update-stat" \
"us: 10, update-progress: { }, download-consent: { state: 3 } }, {" \
" name: GW-3630015-DB31-0x0000, current-version: 3630801-DB314000," \
" terminal-failure: false, update-status: 10, update-progress: { }" \
", download-consent: { state: 3 } }, { name: GW-ECU-3610330-DB01-0" \
"x0059, current-version: 3610814-DB012003, terminal-failure: false" \
", update-status: 10, update-progress: { }, download-consent: { st" \
"ate: 3 } }, { name: GW-ECU-3629310-DB05-0x007B, current-version: " \
"3002            , terminal-failure: false, update-status: 10, upd" \
"ate-progress: { }, download-consent: { state: 3 } }, { name: GW-E" \
"CU-3616330-DB03-0x0077, current-version: 2001            , termin" \
"al-failure: false, update-status: 10, update-progress: { }, downl" \
"oad-consent: { state: 3 } }, { name: GW-ECU-3611015-DB01-0x0032, " \
"current-version: FDCT400DB31H6061, terminal-failure: false, updat" \
"e-status: 10, update-progress: { }, download-consent: { state: 3 " \
"} }, { name: GW-ECU-3748030-DB03-0x005D, current-version: 3748802" \
"-DB053002, terminal-failure: false, update-status: 10, update-pro" \
"gress: { }, download-consent: { state: 3 } }, { name: GW-ECU-3550" \
"020-DB01-0x0041, current-version: BB99860, terminal-failure: fals" \
"e, update-status: 10, update-progress: { }, download-consent: { s" \
"tate: 3 } }, { name: GW-ECU-3630030-DB31-0x0049, current-version:" \
" SW:B.0.4.9, terminal-failure: false, update-status: 10, update-p" \
"rogress: { }, download-consent: { state: 3 } }, { name: GW-ECU-81" \
"12025-DB01-0x0055, current-version: 2000            , terminal-fa" \
"ilure: false, update-status: 10, update-progress: { }, download-c" \
"onsent: { state: 3 } }, { name: GW-ECU-3711030-DB03-0x007A, curre" \
"nt-version: SV1.4, terminal-failure: false, update-status: 10, up" \
"date-progress: { }, download-consent: { state: 3 } }, { name: GW-" \
"ECU-3624115-DB01-0x0045, current-version: 3624811-DB014039, termi" \
"nal-failure: false, update-status: 10, update-progress: { }, down" \
"load-consent: { state: 3 } }, { name: GW-ECU-3785110-DB01-0x0073," \
" current-version: SW:V3.2, terminal-failure: false, update-status" \
": 10, update-progress: { }, download-consent: { state: 3 } }, { n" \
"ame: GW-ECU-3610755-DB03-0x005A, current-version: 3610817-DB03100" \
"8, terminal-failure: false, update-status: 10, update-progress: {" \
" }, download-consent: { state: 3 } }, { name: GW-ECU-3785250-DB05" \
"-0x0072, current-version: 3002            , terminal-failure: fal" \
"se, update-status: 10, update-progress: { }, download-consent: { "

static int large_message() {

    int err = E_XL4BUS_OK;

    test_client_t client1 = {0, .label = f_strdup("client-grp1")};
    test_client_t client2 = {0, .label = f_strdup("client-grp2")};
    test_client_t client3 = {0, .label = f_strdup("ua-rom")};
    test_broker_t broker = { 0};

    do {

        BOLT_SUB(full_test_broker_start(&broker));
        BOLT_SUB(full_test_client_start(&client1, &broker, 1));
        BOLT_SUB(full_test_client_start(&client2, &broker, 1));
        BOLT_SUB(full_test_client_start(&client3, &broker, 1));

        xl4bus_address_t * addr = 0;
        BOLT_SUB(xl4bus_get_identity_addresses(&client1.bus_client.identity, &addr));
        BOLT_SUB(xl4bus_get_identity_addresses(&client2.bus_client.identity, &addr));
        BOLT_SUB(full_test_send_message2(&client3, addr, f_strdup(MESSAGE)));

        test_event_t * event;

        BOLT_SUB(full_test_client_expect_single(0, &client1, &event, TET_CLT_MSG_RECEIVE));
        TEST_CHR_N_EQUAL(event->msg->data, MESSAGE, strlen(MESSAGE));
        full_test_free_event(event);

        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_CLT_MSG_RECEIVE));
        TEST_CHR_N_EQUAL(event->msg->data, MESSAGE, strlen(MESSAGE));
        full_test_free_event(event);

        BOLT_SUB(full_test_client_expect_single(0, &client3, &event, TET_MSG_ACK_OK));
        full_test_free_event(event);

        xl4bus_free_address(addr, 1);

    } while (0);

    full_test_client_stop(&client1, 1);
    full_test_client_stop(&client2, 1);
    full_test_client_stop(&client3, 1);
    full_test_broker_stop(&broker, 1);

    return err;


}

int esync_4880() {

    int err = E_XL4BUS_OK;

    do {

        BOLT_SUB(large_message());

    } while (0);

    return err;

}
