
#ifndef VT_IP_ADDR_H 
#define VT_IP_ADDR_H 1
/**
* @name Constructor and Destructor
* @{
*/


struct VtIpAddr* VtIpAddr_new(void);

/** Get a reference counter */
void VtIpAddr_get(struct VtIpAddr *obj);

/** put a reference counter */
void VtIpAddr_put(struct VtIpAddr **obj);

void VtIpAddr_setApiKey(struct VtIpAddr *vt_ip_addr, const char *api_key);


struct VtResponse * VtIpAddr_getResponse(struct VtIpAddr *vt_ip_addr);

int VtIpAddr_report(struct VtIpAddr *vt_ip_addr, const char *ip_addr_str);

#endif