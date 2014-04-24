#ifndef VT_URL_H
#define VT_URL_H 1

#ifdef  __cplusplus
extern "C" {
#endif

// forward declarations
struct VtUrl;
struct VtResponse;
struct VtObject;

/**
* @ingroup VtApiPage
* @defgroup VtUrl  VtUrl URL scanning object
* @{
*/

/**
 * @brief Create new URL object
 *
 * @param  void
 * @return VtUrl*
 */
struct VtUrl* VtUrl_new(void);

/**
 * @brief Get a reference counter
 *
 * @param  VtUrl object
 * @return void
 */

void VtUrl_get(struct VtUrl *);


/**
 * @brief Put a reference counter
 *
 * @param  Pointer to VtUrl pointer
 * @return void
 */
void VtUrl_put(struct VtUrl **);

/**
 * @brief Stet tha API key
 *
 * @param url_scan VtUrl Object
 * @param api_key your api key
 * @return void
 */
void VtUrl_setApiKey(struct VtUrl *url_scan, const char *api_key);

/**
 * @brief Scan URL 
 * 
 * @param VtUrl   Url scan object
 * @param url    URL to scan
 * @return int  0 if OK or error code
 */

int VtUrl_scan(struct VtUrl *, const char *url);


/**
 * @brief get the report of the URL scan
 * 
 * @param VtUrl scan object
 * @param url  URL to get report on
 * @param scan set to true if you wish to rescan
 * @param all_info  set true if you wall aditional info.  (Private API Key Only) 
 * @return int
 */
int VtUrl_report(struct VtUrl *, const char *url, bool scan, bool all_info);


/**
 * @brief Get response object
 *
 * @param url_scan VtUrl Object
 * @return VtResponse*
 */
struct VtResponse * VtUrl_getResponse(struct VtUrl *url_scan);

/**
*  @}
*/

#ifdef  __cplusplus
}
#endif /*cplusplus*/

#endif
