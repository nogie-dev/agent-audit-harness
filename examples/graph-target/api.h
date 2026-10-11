#ifndef AUDIT_GRAPH_API_H
#define AUDIT_GRAPH_API_H
int entry(int value);
int parse(int value);
int callback_entry(int value, int (*callback)(int));
#endif
