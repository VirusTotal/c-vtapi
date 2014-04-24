#ifndef VT_DEBUG_H
#define VT_DEBUG_H 1


#ifdef  __cplusplus
extern "C" {
#endif

/**
 * @brief Set the debug level for printing
 *
 * @param level 0  for no debug,  1 or 2 for a little.  9 for max debug printing
 * @return void
 */
void VtDebug_setDebugLevel(int level);

#ifdef  __cplusplus
}
#endif /*cplusplus*/

#endif