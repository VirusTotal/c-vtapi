#ifndef VT_RESPONSE_H
#define VT_RESPONSE_H 1


struct VtResponse* VtResponse_new(void);

/** Get a reference counter */
void VtResponse_get(struct VtResponse *VtResponse);


/** put a reference counter */
void VtResponse_put(struct VtResponse **VtResponse);

char * VtResponse_getVerboseMsg(struct VtResponse *response, char *buf, int buf_siz);

int VtResponse_getResponseCode(struct VtResponse *response);

json_t * VtResponse_toJSON(struct VtResponse *response);

char * VtResponse_toJSONstr(struct VtResponse *response);

int VtResponse_fromJSON(struct VtResponse *response, json_t *json);

int VtResponse_fromJSONstr(struct VtResponse *response, const char *json_str);


#endif