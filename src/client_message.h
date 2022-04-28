#ifndef _XL4BUS_CLIENT_MESSAGE_H
#define _XL4BUS_CLIENT_MESSAGE_H

#if ESYNC_ALLIANCE
#define FCT_BUS_MESSAGE_PREFIX "esync"
#else
#define FCT_BUS_MESSAGE_PREFIX "xl4"
#endif

#define FCT_BUS_MESSAGE_QUERY_UPDATE_RESPONSE 			FCT_BUS_MESSAGE_PREFIX ".query-updates"
#define MSG_TYPE_REG_REQUEST 							FCT_BUS_MESSAGE_PREFIX  "bus.registration-request"
#define MSG_TYPE_REQ_DESTINATIONS 						FCT_BUS_MESSAGE_PREFIX "bus.request-destinations"
#define MSG_TYPE_REQ_CERT 								FCT_BUS_MESSAGE_PREFIX "bus.request-cert"
#define MSG_TYPE_CERT_DETAILS 							FCT_BUS_MESSAGE_PREFIX  "bus.cert-details"
#define MSG_TYPE_MESSAGE_CONFIRM 						FCT_BUS_MESSAGE_PREFIX "bus.message-confirm"
#define MSG_TYPE_KEY_INFO 								FCT_BUS_MESSAGE_PREFIX "bus.key-info"
#define MSG_TYPE_REQ_KEY 								FCT_BUS_MESSAGE_PREFIX "bus.request-key"
#define MSG_TYPE_PRESENCE 								FCT_BUS_MESSAGE_PREFIX "bus.presence"
#define MSG_TYPE_ALG_SUPPORTED  						FCT_BUS_MESSAGE_PREFIX "bus.alg-supported"
#define MSG_TYPE_REQUEST_CERT 							FCT_BUS_MESSAGE_PREFIX "bus.request-cert"
#define MSG_TYPE_DESTINATION_INFO 						FCT_BUS_MESSAGE_PREFIX "bus.destination-info"
#define  FCT_BUS_MESSAGE								"application/vnd."FCT_BUS_MESSAGE_PREFIX".busmessage+json"
#define FCT_TRUST_MESSAGE 								"application/vnd."FCT_BUS_MESSAGE_PREFIX".busmessage-trust+json"

#endif
