/*
Copyright 2014 VirusTotal S.L. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
