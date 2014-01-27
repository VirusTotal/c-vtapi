
#ifndef VT_IP_ADDR_H 
#define VT_IP_ADDR_H 1

struct VtIpAddr;
struct VtResponse;

/**
* @ingroup VtApiPage
* @defgroup VtIpAddr  VtIpAddr object for getting reports on IP addresses.
* @{
*/


/**
 * @brief Create new Ojbect
 * 
 * @return VtIpAddr object pointer
 */

struct VtIpAddr* VtIpAddr_new(void);

/** Get a reference counter */
void VtIpAddr_get(struct VtIpAddr *obj);

/** put a reference counter */
void VtIpAddr_put(struct VtIpAddr **obj);

/**
 * @brief Set API KEY
 * 
 * @param vt_ip_addr ...
 * @param api_key Your API Kety
 * @return void
 */

void VtIpAddr_setApiKey(struct VtIpAddr *vt_ip_addr, const char *api_key);


struct VtResponse * VtIpAddr_getResponse(struct VtIpAddr *vt_ip_addr);

/**
 * @brief Get the report on a IP address
 * 
 * @param vt_ip_addr ...
 * @param ip_addr_str ...
 * @return int
 */
int VtIpAddr_report(struct VtIpAddr *vt_ip_addr, const char *ip_addr_str);


/**
*  @}
*/

#endif