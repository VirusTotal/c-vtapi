#ifndef VT_DOMAIN_H
#define VT_DOMAIN_H 1


#ifdef  __cplusplus
extern "C" {
#endif

struct VtDomain;
struct VtResponse;

/**
* @ingroup VtApiPage
* @defgroup VtDomain VtDomain checking service
* @{
*/
struct VtDomain* VtDomain_new(void);


/**
 * @brief Get a reference pointer
 *
 * @param obj Domain object
 * @return void
 */
void VtDomain_get(struct VtDomain *obj);

/**
 * @brief Put a reference counter
 *
 * @param obj ...
 * @return void
 */
void VtDomain_put(struct VtDomain **obj);


/**
 * @brief Set API key
 * 
 * @param vt_domain VtDomain object
 * @param api_key your API key
 * @return void
 */
void VtDomain_setApiKey(struct VtDomain *vt_domain, const char *api_key);

/**
 * @brief Get response object
 *
 * @param vt_domain ...
 * @return VtResponse*
 */
struct VtResponse * VtDomain_getResponse(struct VtDomain *vt_domain);

/**
 * @brief get the report on a domain
 * 
 * @param vt_domain ...
 * @param domain_name_str Domain Name to get report on
 * @return int.  0 for OK, or 
 */
int VtDomain_report(struct VtDomain *vt_domain, const char *domain_name_str);

/**
*  @}
*/

#ifdef  __cplusplus
}
#endif /*cplusplus*/

#endif
