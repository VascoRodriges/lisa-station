/* The declared scope is four guarded roles, not every firmware sender/relay.
 * No callback accepts an external PID/command. Never short-circuit best-effort
 * stop or role verification because another role has failed. */
#ifndef LISA_COMPOSITE_ROLES_H
#define LISA_COMPOSITE_ROLES_H
#include "closed_transition.h"

#define COMPOSITE_ROLE_COUNT 4
static const unsigned composite_groups[COMPOSITE_ROLE_COUNT]={57342,57343,57344,57345};
static const char *const composite_names[COMPOSITE_ROLE_COUNT]={"quasar","diagnostics","collector","telemetry"};
struct composite_roles {
    int (*deny_all)(void *context);
    int (*stop_role)(void *context,unsigned role);
    int (*role_absent)(void *context,unsigned role);
    void *context;
};
static inline int composite_valid(const struct composite_roles *roles) {
    return roles&&roles->deny_all&&roles->stop_role&&roles->role_absent;
}
static inline int composite_deny(void *pointer) {
    struct composite_roles *roles=pointer;
    return composite_valid(roles)?roles->deny_all(roles->context):-1;
}
static inline int composite_stop(void *pointer) {
    struct composite_roles *roles=pointer; int failed=0;
    if(!composite_valid(roles)) return -1;
    /* Main senders first; independent diagnostics, collector, telemetry next.
     * The common permit has already been revoked by the durable executor. */
    for(unsigned i=0;i<COMPOSITE_ROLE_COUNT;++i) failed|=!!roles->stop_role(roles->context,i);
    return failed?-1:0;
}
static inline int composite_verify(void *pointer) {
    struct composite_roles *roles=pointer; int failed=0;
    if(!composite_valid(roles)) return -1;
    failed|=!!roles->deny_all(roles->context);
    for(unsigned i=0;i<COMPOSITE_ROLE_COUNT;++i) failed|=!!roles->role_absent(roles->context,i);
    return failed?-1:0;
}
#endif
