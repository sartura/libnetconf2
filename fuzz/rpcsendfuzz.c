#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>

#include "fuzz/config.h"
#include <messages_p.h>
#include <session_client.h>
#include <session_p.h>
#include <session_server.h>

struct nc_session *server_session;
struct nc_session *client_session;
pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
int glob_state;
struct ly_ctx *ctx;

static struct nc_session *test_new_session(NC_SIDE side) {
  struct nc_session *sess;

  sess = calloc(1, sizeof *sess);
  if (!sess) {
    return NULL;
  }

  sess->side = side;

  if (side == NC_SERVER) {
    sess->opts.server.rpc_lock = malloc(sizeof *sess->opts.server.rpc_lock);
    sess->opts.server.rpc_cond = malloc(sizeof *sess->opts.server.rpc_cond);
    sess->opts.server.rpc_inuse = malloc(sizeof *sess->opts.server.rpc_inuse);
    if (!sess->opts.server.rpc_lock || !sess->opts.server.rpc_cond ||
        !sess->opts.server.rpc_inuse) {
      goto error;
    }
    pthread_mutex_init(sess->opts.server.rpc_lock, NULL);
    pthread_cond_init(sess->opts.server.rpc_cond, NULL);
    *sess->opts.server.rpc_inuse = 0;
  }

  sess->io_lock = malloc(sizeof *sess->io_lock);
  if (!sess->io_lock) {
    goto error;
  }
  pthread_mutex_init(sess->io_lock, NULL);

  return sess;

error:
  if (side == NC_SERVER) {
    free(sess->opts.server.rpc_lock);
    free(sess->opts.server.rpc_cond);
    free((int *)sess->opts.server.rpc_inuse);
  }
  free(sess);
  return NULL;
}

static int setup_sessions(void) {
  int sock[2];

  /* create communication channel */
  socketpair(AF_UNIX, SOCK_STREAM, 0, sock);

  /* create server session */
  server_session = test_new_session(NC_SERVER);
  server_session->status = NC_STATUS_RUNNING;
  server_session->id = 1;
  server_session->ti_type = NC_TI_FD;
  server_session->ti.fd.in = sock[0];
  server_session->ti.fd.out = sock[0];
  server_session->ctx = ctx;
  server_session->flags = NC_SESSION_SHAREDCTX;

  /* create client session */
  client_session = test_new_session(NC_CLIENT);
  client_session->status = NC_STATUS_RUNNING;
  client_session->id = 1;
  client_session->ti_type = NC_TI_FD;
  client_session->ti.fd.in = sock[1];
  client_session->ti.fd.out = sock[1];
  client_session->ctx = ctx;
  client_session->flags = NC_SESSION_SHAREDCTX;
  client_session->opts.client.msgid = 50;

  return 0;
}

struct nc_server_reply *my_get_rpc_clb(struct lyd_node *rpc,
                                       struct nc_session *session) {
  return nc_server_reply_ok();
}

struct nc_server_reply *my_getconfig_rpc_clb(struct lyd_node *rpc,
                                             struct nc_session *session) {
  struct lyd_node *data;

  data = lyd_new_path(NULL, session->ctx, "/ietf-netconf:get-config/data", NULL,
                      LYD_ANYDATA_CONSTSTRING, LYD_PATH_OPT_OUTPUT);

  return nc_server_reply_data(data, NC_WD_EXPLICIT, NC_PARAMTYPE_FREE);
}

struct nc_server_reply *my_commit_rpc_clb(struct lyd_node *rpc,
                                          struct nc_session *session) {

  /* update state */
  pthread_mutex_lock(&state_lock);
  glob_state = 1;

  /* wait until the client receives the notification */
  while (glob_state != 3) {
    pthread_mutex_unlock(&state_lock);
    usleep(100000);
    pthread_mutex_lock(&state_lock);
  }
  pthread_mutex_unlock(&state_lock);

  return nc_server_reply_ok();
}

char *read_buf(void) {
  char *buf = NULL;
  char c;
  size_t len = 0;

  while ((c = getc(stdin))) {
    buf = realloc(buf, len + 1);
    if (buf == NULL) {
      exit(1);
    }

    buf[len] = c;
    len++;
  }

  buf = realloc(buf, len + 1);
  if (buf == NULL) {
    exit(1);
  }

  buf[len] = 0;

  return buf;
}

int main(int argc, char **argv) {
  int ret;
  const struct lys_module *module;
  const struct lys_node *node;
  struct nc_rpc *rpc;
  NC_MSG_TYPE msgtype;
  uint64_t msgid;
  struct nc_reply *reply;
  struct nc_pollsession *ps;
  char *buf;

  setup_sessions();

  ctx = ly_ctx_new(FUZZ_DIR "../schemas", 0);

  /* load modules */
  module = ly_ctx_load_module(ctx, "ietf-netconf-acm", NULL);

  module = ly_ctx_load_module(ctx, "ietf-netconf", NULL);
  ret = lys_features_enable(module, "candidate");

  module = ly_ctx_load_module(ctx, "nc-notifications", NULL);

  /* set RPC callbacks */
  node = ly_ctx_get_node(module->ctx, NULL, "/ietf-netconf:get", 0);
  lys_set_private(node, my_get_rpc_clb);

  node = ly_ctx_get_node(module->ctx, NULL, "/ietf-netconf:get-config", 0);
  lys_set_private(node, my_getconfig_rpc_clb);

  node = ly_ctx_get_node(module->ctx, NULL, "/ietf-netconf:commit", 0);
  lys_set_private(node, my_commit_rpc_clb);

  while (__AFL_LOOP(100)) {
    buf = read_buf();
    rpc = nc_rpc_act_generic_xml(buf, NC_PARAMTYPE_CONST);
    if (rpc == NULL) {
      printf("RPC is NULL\n");
      return 1;
    }

    msgtype = nc_send_rpc(client_session, rpc, 0, &msgid);

    ps = nc_ps_new();
    nc_ps_add_session(ps, server_session);

    ret = nc_ps_poll(ps, 0, NULL);

    nc_ps_free(ps);

    msgtype = nc_recv_reply(client_session, rpc, msgid, 0, 0, &reply);

    nc_rpc_free(rpc);
    nc_reply_free(reply);
    free(buf);
  }

  return 0;
}