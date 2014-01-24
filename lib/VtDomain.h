#ifndef VT_DOMAIN_H
#define VT_DOMAIN_H 1


struct VtDomain* VtDomain_new(void);

/** Get a reference counter */
void VtDomain_get(struct VtDomain *obj);

/** put a reference counter */
void VtDomain_put(struct VtDomain **obj);
void VtDomain_setApiKey(struct VtDomain *vt_ip_addr, const char *api_key);

struct VtResponse * VtDomain_getResponse(struct VtDomain *vt_ip_addr);

int VtDomain_report(struct VtDomain *vt_ip_addr, const char *ip_addr_str);


#endif