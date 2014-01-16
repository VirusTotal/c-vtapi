#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "vtcapi-config.h"
#endif


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <jansson.h>
#include <stdbool.h>


#include "VtObject.h"
#include "VtResponse.h"

#include "vtcapi_common.h"

struct VtResponse
{
	VT_OBJECT_COMMON
	int response_code;
	char *verbose_msg;
    json_error_t json_error;
	json_t *json_data;
};


/**
* @name Constructor and Destructor
* @{
*/

/**
*  VtObjects constructor
*  @arg VtObject that was just allocated
*/
int VtResponse_constructor(struct VtObject *obj)
{
	struct VtResponse *response = (struct VtResponse *)obj;

	DBG(DGB_LEVEL_MEM, " constructor %p\n", response);

	return 0;
}


/**
*  VtObjects destructor
*  @arg VtObject that is going to be free'd
*/
int VtResponse_destructor(struct VtObject *obj)
{
	struct VtResponse *response = (struct VtResponse *)obj;

	DBG(DGB_LEVEL_MEM, " destructor %p\n", response);
	
	if (response->verbose_msg)
		free(response->verbose_msg);

	
	return 0;
}

// static int VtResponse_objectFromJSON(struct VtObject *response, json_t *json)
// {
// 	return VtResponse_fromJSON((struct VtResponse *)response, json);
// }


/** @} */


static struct VtObject_ops obj_ops = {
	.obj_type           = "VtResponse",
	.obj_size           = sizeof(struct VtResponse),
	.obj_constructor    = VtResponse_constructor,
	.obj_destructor     = VtResponse_destructor,
// 	.obj_from_json      = VtResponse_objectFromJSON,
};

static struct VtResponse* VtResponse_alloc(struct VtObject_ops *ops)
{
	struct VtResponse *VtResponse;

	VtResponse = (struct VtResponse*) VtObject_alloc(ops);
	return VtResponse;
}


struct VtResponse* VtResponse_new(void)
{
	struct VtResponse *VtResponse = VtResponse_alloc(&obj_ops);

	return VtResponse;
}

/** Get a reference counter */
void VtResponse_get(struct VtResponse *VtResponse)
{
	VtObject_get((struct VtObject*) VtResponse);
}

/** put a reference counter */
void VtResponse_put(struct VtResponse **resp)
{
    struct VtResponse *response = *resp;
    
    if (response->json_data) {
        json_decref(response->json_data);
    }
    
	VtObject_put((struct VtObject**) resp);
}

#define VT_RESPONSE_DECLARE_STR_GET(fn_name, member_name) char * VtResponse_##fn_name##(struct VtResponse *response, char *buf, int buf_siz) \
{ \
	return strncpy(buf, response->##member_name##, buf_siz);\
}


char * VtResponse_getVerboseMsg(struct VtResponse *response, char *buf, int buf_siz)
{
	return strncpy(buf, response->verbose_msg, buf_siz);
}



int VtResponse_getIntValue(struct VtResponse *response, const char *key, int *value)
{
    json_t *jdata;
	
	if (!response->json_data) {
		ERROR("not set\n");
		return -1;
	}

	jdata = json_object_get(response->json_data, key);
	if (!jdata) {
		ERROR("missing key '%s'\n", key)
		return -1;
	}
	*value = json_integer_value(jdata);

    return 0; // OK
}

char *VtResponse_getString(struct VtResponse *response, const char *key)
{
    json_t *jdata;
	const char *str;
	
	if (!response->json_data) {
		ERROR("not set\n");
		return NULL;
	}
	
	jdata = json_object_get(response->json_data, key);
	if (!jdata) {
		ERROR("missing key '%s'\n", key)
		return NULL;
	}
	str = json_string_value(jdata);
	if (!str) {
		return NULL;
	}
	return strdup(str);
}

int VtResponse_getResponseCode(struct VtResponse *response, int *code)
{
    return VtResponse_getIntValue(response, "response_code", code);
}


char * VtResponse_toJSONstr(struct VtResponse *response, int flags)
{
    char *s;
	
    if (debug_level || (flags | VT_JSON_FLAG_INDENT) )
        s = json_dumps(response->json_data, JSON_INDENT(4));
    else
        s = json_dumps(response->json_data, JSON_COMPACT);

	return s;
}

int VtResponse_fromJSON(struct VtResponse *response, json_t *json)
{
	json_t *json_data;
	
	json_data = json_object_get(json, "response_code");
	if (json_data) {
		response->response_code = json_integer_value(json_data);
	} else {
		ERROR("Protocol error missing 'response_code'\n");
	}

	json_data = json_object_get(json, "verbose_msg");
	if (json_data) {
		response->verbose_msg = strdup(json_string_value(json_data));
	} else {
		ERROR("Protocol error missing 'verbose_msg'\n");
	}

	return 0;
}

int VtResponse_fromJSONstr(struct VtResponse *response, const char *json_str)
{
	
	response->json_data =json_loads(json_str, 0, &response->json_error);
	if (!response->json_data) {
		ERROR("Parsing\n");
		return -1;
	}
	return 0;
}

json_t * VtResponse_getJanssonObj(struct VtResponse *response, const char *json_str)
{
	return response->json_data;
}
