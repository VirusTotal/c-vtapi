#ifndef VT_DOMAIN_H
#define VT_DOMAIN_H 1

struct VtDomain;
struct VtResponse;

/**
* @ingroup VtApiPage
* @defgroup VtDomain VtDomain checking service
* @{
*/
struct VtDomain* VtDomain_new(void);

/** Get a reference counter */
void VtDomain_get(struct VtDomain *obj);

/** put a reference counter */
void VtDomain_put(struct VtDomain **obj);


/**
 * @brief Set API key
 * 
 * @param vt_domain VtDomain object
 * @param api_key your API key
 * @return void
 */
void VtDomain_setApiKey(struct VtDomain *vt_domain, const char *api_key);

struct VtResponse * VtDomain_getResponse(struct VtDomain *vt_ip_addr);

/**
 * @brief get the report on a domain
 * 
 * @param vt_ip_addr ...
 * @param domain_name_str Domain Name to get report on
 * @return int
 */
int VtDomain_report(struct VtDomain *vt_ip_addr, const char *domain_name_str);

/**
*  @}
*/

#endif