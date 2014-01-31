#ifndef VT_COMMENTS_H
#define VT_COMMENTS_H 1

struct VtComments;

struct VtComments* VtComments_new(void);

/** Get a reference counter */
void VtComments_get(struct VtComments *vt_comments);

/** put a reference counter */
void VtComments_put(struct VtComments **vt_comments);

void VtComments_setApiKey(struct VtComments *vt_comments, const char *api_key);
void VtComments_setBefore(struct VtComments *vt_comments, const char *value);
int VtComments_setResource(struct VtComments *vt_comments, const char *value);

struct VtResponse * VtComments_getResponse(struct VtComments *vt_comments);

int VtComments_add(struct VtComments *vt_comments, const char *comment);


int VtComments_retrieve(struct VtComments *vt_comments);

#endif
