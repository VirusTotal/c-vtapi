
#ifndef VT_IP_ADDR_H 
#define VT_IP_ADDR_H 1

#ifdef  __cplusplus
extern "C" {
#endif

struct VtIpAddr;
struct VtResponse;

/**
* @ingroup VtApiPage
* @defgroup VtIpAddr  VtIpAddr object for getting reports on IP addresses.
* @{
*/


/**
 * @brief Create new Object
 * 
 * @return VtIpAddr object pointer. or null on erro
 */
struct VtIpAddr* VtIpAddr_new(void);


/**
 * @brief Get a reference counter
 *
 * @param obj VtIpAddr object
 * @return void
 */
void VtIpAddr_get(struct VtIpAddr *obj);


/**
 * @brief Put a reference counter
 *
 * @param obj ...
 * @return void
 */
void VtIpAddr_put(struct VtIpAddr **obj);

/**
 * @brief Set API KEY
 * 
 * @param vt_ip_addr ...
 * @param api_key Your API Kety
 * @return void
 */
void VtIpAddr_setApiKey(struct VtIpAddr *vt_ip_addr, const char *api_key);



/**
 * @brief Get the respose object
 *
 * @param vt_ip_addr VtIpAddr object
 * @return VtResponse*
 */
struct VtResponse * VtIpAddr_getResponse(struct VtIpAddr *vt_ip_addr);

/**
 * @brief Get the report on a IP address
 * 
 * @param vt_ip_addr ...
 * @param ip_addr_str ...
 * @return int.  0 for OK, or error code
 */
int VtIpAddr_report(struct VtIpAddr *vt_ip_addr, const char *ip_addr_str);


/**
*  @}
*/

#ifdef  __cplusplus
}
#endif /*cplusplus*/

#endif
