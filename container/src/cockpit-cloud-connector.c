#define G_LOG_DOMAIN "cockpit-cloud-connector"
#include <glib.h>
#include <locale.h>
#include <stdlib.h>
#include <gio/gunixsocketaddress.h>

/* {{{1 Helpers */
gboolean
throw (GError **error,
       const gchar *fmt,
       ...)
{
  va_list ap;
  va_start (ap, fmt);
  if (error)
    *error = g_error_new_valist (G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE, fmt, ap);
  va_end (ap);

  return FALSE;
}

/* {{{1 Server */

typedef struct
{
  gboolean should_exit;

  GOutputStream *tcp_primary;
  GQueue *unix_waiting;

  GTlsCertificate *certificate;
  GTlsCertificate *expected_peer_certificate;
} Server;

static void
server_request_connection (Server *self)
{
  /* NB: in theory, we need to do this async, but the "unix"
   * side of this service is cockpit-ws, and it's never going to
   * simultaneously try to open enough sessions to fill the TCP
   * buffer.  In fact, the number will almost always be 0 or 1.
   */
  g_debug ("Requesting additional TCP connection");
  g_autoptr(GError) error = NULL;
  if (!g_output_stream_write (self->tcp_primary, "-", 1, NULL, &error))
    {
      g_warning ("Error writing to the primary TCP connection: %s", error->message);
      self->should_exit = TRUE;
    }
}

static gboolean
server_on_unix_incoming (GSocketService *service,
                         GSocketConnection *connection,
                         GObject *source_object,
                         gpointer user_data)
{
  Server *self = user_data;

  g_debug ("Incoming unix connection");

  /* Add ourselves to the queue and request an incoming connection */
  g_queue_push_tail (self->unix_waiting, g_object_ref (connection));
  if (self->tcp_primary)
    server_request_connection (self);

  return TRUE;
}

static void
server_tcp_primary_read_ready (GObject *source_object,
                               GAsyncResult *result,
                               gpointer user_data)
{
  Server *self = user_data;

  /* We should *technically* call this, even though we don't care. */
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) bytes = g_input_stream_read_bytes_finish (G_INPUT_STREAM (source_object), result, &error);
  if (!bytes)
    g_warning ("Error reading from primary TCP connection: %s", error->message);

  g_debug ("Exiting due to data from primary TCP connection.");

  self->should_exit = TRUE;
}

static void
server_tls_handshake_ready (GObject *source_object,
                            GAsyncResult *result,
                            gpointer user_data)
{
  /* We assume the reference given to g_tls_connection_handshake_async() */
  g_autoptr(GTlsConnection) connection = G_TLS_CONNECTION (source_object);
  Server *self = user_data;

  g_autoptr(GError) error = NULL;
  if (!g_tls_connection_handshake_finish (connection, result, &error))
    {
      g_warning ("Dropping incoming connection due to TLS handshake failure: %s", error->message);
      return;
    }

  g_debug ("TLS handshake complete.");

  /* We're authenticated. */
  if (self->tcp_primary == NULL)
    {
      /* Cool.  We're it! */
      g_debug ("Got primary TCP connection.");

      self->tcp_primary = g_object_ref (g_io_stream_get_output_stream (G_IO_STREAM (connection)));

      /* If the client ever sends anything on — or closes — the primary
       * connection, then the server needs to exit.
       */
      g_input_stream_read_bytes_async (G_INPUT_STREAM (g_io_stream_get_input_stream (G_IO_STREAM (connection))),
                                       1, G_PRIORITY_DEFAULT, NULL, server_tcp_primary_read_ready, self);

      /* If there are already unix connections waiting, then we need to
       * request that many incoming connections.
       */
      gint n = g_queue_get_length (self->unix_waiting);
      for (gint i = 0; i < n; i++)
        server_request_connection (self);
    }
  else if (!g_queue_is_empty (self->unix_waiting))
    {
      /* Someone was waiting for us */
      g_autoptr(GSocketConnection) unix_connection = g_queue_pop_head (self->unix_waiting);

      /* ... magic. */
      g_io_stream_splice_async (G_IO_STREAM (connection), G_IO_STREAM (unix_connection),
                                G_IO_STREAM_SPLICE_CLOSE_STREAM1 | G_IO_STREAM_SPLICE_CLOSE_STREAM2 |
                                G_IO_STREAM_SPLICE_WAIT_FOR_BOTH, G_PRIORITY_DEFAULT, NULL, NULL, NULL);
    }

  /* Otherwise we didn't request this connection.  Let it drop. */
}

static gboolean
server_on_accept_certificate (GTlsConnection *connection,
                              GTlsCertificate *peer_cert,
                              GTlsCertificateFlags errors,
                              gpointer user_data)
{
  Server *self = user_data;

  g_debug ("Verifying peer certificate");

  return g_tls_certificate_is_same (peer_cert, self->expected_peer_certificate);
}

static gboolean
server_on_tcp_incoming (GSocketService *service,
                        GSocketConnection *connection,
                        GObject *source_object,
                        gpointer user_data)
{
  Server *self = user_data;

  g_debug ("Incoming TCP connection.");

  /* First things first: TLS please. */
  g_autoptr(GError) error = NULL;
  GTlsConnection *tls_connection = G_TLS_CONNECTION (g_tls_server_connection_new (G_IO_STREAM (connection),
                                                                                  self->certificate, &error));
  g_assert_no_error (error);
  g_assert (tls_connection);

  /* Disable system certificate validation */
  g_tls_connection_set_database (tls_connection, NULL);
  g_object_set (G_OBJECT (tls_connection),
                "authentication-mode", G_TLS_AUTHENTICATION_REQUIRED,
                NULL);
  g_signal_connect (tls_connection, "accept-certificate",
                    G_CALLBACK (server_on_accept_certificate), self);

  /* We forward our reference to tls_connection to the handler */
  g_debug ("Doing handshake.");
  g_tls_connection_handshake_async (tls_connection, G_PRIORITY_DEFAULT,
                                    NULL, server_tls_handshake_ready, self);

  return TRUE;
}

gboolean
server (gchar **args,
        GTlsCertificate *certificate,
        GTlsCertificate *peer_certificate,
        GError **error)
{
  g_auto(GStrv) path = NULL;
  g_autofree gchar *address = NULL;
  gint port = 443;

  g_autoptr(GOptionContext) context = g_option_context_new ("PATH");
  g_option_context_set_summary (context, "Accept incoming TCP connections and make them available on unix socket PATH.");
  g_option_context_add_main_entries (context, (GOptionEntry[]) {
    { "address", 'a', 0, G_OPTION_ARG_STRING, &address, "Address to bind to (default: all)", "ADDRESS" },
    { "port", 'p', 0, G_OPTION_ARG_INT, &port, "Port to bind to (default: 443)", "PORT" },
    { G_OPTION_REMAINING, '\0', 0, G_OPTION_ARG_STRING_ARRAY, &path },
    { NULL } }, NULL);
  if (!g_option_context_parse_strv (context, &args, error))
    return FALSE;

  if (!path || !path[0] || path[1])
    return throw (error, "One unix socket path is required");

  g_autoptr(GSocketService) unix_service = g_socket_service_new ();
  g_debug ("Server unix address is %s", path[0]);
  g_autoptr(GSocketAddress) unix_address = g_unix_socket_address_new (path[0]);
  if (!g_socket_listener_add_address (G_SOCKET_LISTENER (unix_service), unix_address, G_SOCKET_TYPE_STREAM,
                                      G_SOCKET_PROTOCOL_DEFAULT, NULL, NULL, error))
    return FALSE;

  g_autoptr(GSocketService) tcp_service = g_socket_service_new ();
  if (address)
    {
      g_debug ("Server listens on tcp %s/%u", address, port);
      g_autoptr(GSocketAddress) tcp_address = g_inet_socket_address_new_from_string (address, port);
      if (!g_socket_listener_add_address (G_SOCKET_LISTENER (tcp_service), tcp_address, G_SOCKET_TYPE_STREAM,
                                          G_SOCKET_PROTOCOL_DEFAULT, NULL, NULL, error))
        return FALSE;
    }
  else
    {
      g_debug ("Server listens on tcp port %u", port);
      if (!g_socket_listener_add_inet_port (G_SOCKET_LISTENER (tcp_service), port, NULL, error))
        return FALSE;
    }

  Server self = {
    .unix_waiting = g_queue_new (),
    .certificate = certificate,
    .expected_peer_certificate = peer_certificate
  };
  g_signal_connect (unix_service, "incoming", G_CALLBACK (server_on_unix_incoming), &self);
  g_signal_connect (tcp_service, "incoming", G_CALLBACK (server_on_tcp_incoming), &self);

  while (!self.should_exit)
    g_main_context_iteration (NULL, TRUE);

  g_queue_free_full (self.unix_waiting, g_object_unref);

  return TRUE;
}

/* {{{1 Client */

typedef struct
{
  GSocketClient *socket_client;
  GSocketConnectable *connectable;
  GTlsCertificate *certificate;
  GTlsCertificate *expected_peer_certificate;
  GInputStream *primary;
  gboolean should_exit;
  const gchar * const *command;
} Client;

static void
client_on_connect_ready (GObject *source_object,
                         GAsyncResult *result,
                         gpointer user_data)
{
  Client *self = user_data;

  g_autoptr(GError) error = NULL;
  g_autoptr(GSocketConnection) connection = g_socket_client_connect_finish (self->socket_client, result, &error);
  if (connection == NULL)
    {
      /* This is just about the worst thing that can happen...
       *
       * We tried to make the connection, but it failed.  Meanwhile, the
       * server is *probably* still waiting for us.
       *
       * Try again?  Complete shutdown?  Figure something else out later?
       *
       * ABORT!
       */
      g_assert_not_reached();
    }

  g_debug ("Connected to server.  Starting program.");

  /* We can't just pass the connection via fds to the subprocess,
   * because it's a TLS connection and we need to keep doing the
   * encryption on behalf of the subprocess.  Spawn + splice.
   */
  g_autoptr(GSubprocess) subprocess = g_subprocess_newv (self->command,
                                                         G_SUBPROCESS_FLAGS_STDIN_PIPE |
                                                         G_SUBPROCESS_FLAGS_STDOUT_PIPE,
                                                         &error);
  if (subprocess == NULL)
    {
      g_warning ("Couldn't spawn subprocess: %s", error->message);
      /* That's not likely to get better on a second try... */
      self->should_exit = TRUE;
    }

  /* ... magic. */
  g_autoptr(GIOStream) subprocess_stdio = g_simple_io_stream_new (g_subprocess_get_stdout_pipe (subprocess),
                                                                  g_subprocess_get_stdin_pipe (subprocess));
  g_io_stream_splice_async (G_IO_STREAM (connection), G_IO_STREAM (subprocess_stdio),
                            G_IO_STREAM_SPLICE_CLOSE_STREAM1 | G_IO_STREAM_SPLICE_CLOSE_STREAM2 |
                            G_IO_STREAM_SPLICE_WAIT_FOR_BOTH, G_PRIORITY_DEFAULT, NULL, NULL, NULL);
}

static void
client_primary_read_ready (GObject *source_object,
                           GAsyncResult *result,
                           gpointer user_data)
{
  Client *self = user_data;

  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) bytes = g_input_stream_read_bytes_finish (self->primary, result, &error);
  if (!bytes)
    {
      g_warning ("Error reading from primary TCP connection: %s", error->message);
      self->should_exit = TRUE;
      return;
    }

  if (g_bytes_get_size (bytes) == 0)
    {
      g_debug ("Primary connection got EOF.  Exiting.");
      self->should_exit = TRUE;
      return;
    }

  g_debug ("Server requested that we spawn an instance.  Connecting first.");

  /* Otherwise, we just got a request to spawn a new instance of our command. */
  g_socket_client_connect_async (self->socket_client, self->connectable, NULL,
                                 client_on_connect_ready, self);

  /* ...and set ourselves up to read again. */
  g_input_stream_read_bytes_async (self->primary, 1, G_PRIORITY_DEFAULT, NULL, client_primary_read_ready, self);
}

static gboolean
client_on_accept_certificate (GTlsConnection *connection,
                              GTlsCertificate *peer_cert,
                              GTlsCertificateFlags errors,
                              gpointer user_data)
{
  Client *self = user_data;

  g_debug ("Verifying peer certificate");

  return g_tls_certificate_is_same (peer_cert, self->expected_peer_certificate);
}


static void
client_on_socket_client_event (GSocketClient *client,
                               GSocketClientEvent event,
                               GSocketConnectable *connectable,
                               GIOStream *connection,
                               gpointer user_data)
{
  Client *self = user_data;

  if (event == G_SOCKET_CLIENT_TLS_HANDSHAKING)
    {
      GTlsConnection *tls_connection = G_TLS_CONNECTION (connection);

      /* Disable system certificate validation */
      g_tls_connection_set_database (tls_connection, NULL);
      g_tls_connection_set_certificate (tls_connection, self->certificate);
      g_signal_connect (tls_connection, "accept-certificate", G_CALLBACK (client_on_accept_certificate), self);
    }
}

gboolean
client (gchar **args,
        GTlsCertificate *certificate,
        GTlsCertificate *peer_certificate,
        GError **error)
{
  g_auto(GStrv) command = NULL;
  g_autofree gchar *host = NULL;
  gint port = 443;

  g_autoptr(GOptionContext) context = g_option_context_new ("COMMAND ...");
  g_option_context_set_summary (context, "Forward instances of COMMAND to a server");
  g_option_context_add_main_entries (context, (GOptionEntry[]) {
    { "host", 'h', 0, G_OPTION_ARG_STRING, &host, "Host to connect to (required)", "HOST" },
    { "port", 'p', 0, G_OPTION_ARG_INT, &port, "Port to connect to (default: 443)", "PORT" },
    { G_OPTION_REMAINING, '\0', 0, G_OPTION_ARG_STRING_ARRAY, &command },
    { NULL } }, NULL);
  if (!g_option_context_parse_strv (context, &args, error))
    return FALSE;

  if (!host)
    return throw (error, "--host is required");

  if (!command || !command[0] || !*command[0])
    return throw (error, "A command is required");

  g_autoptr(GSocketConnectable) connectable = g_network_address_new (host, port);
  g_autoptr(GSocketClient) socket_client = g_socket_client_new ();
  g_socket_client_set_tls (socket_client, TRUE);

  Client self = {
    .socket_client = socket_client,
    .connectable = connectable,
    .certificate = certificate,
    .expected_peer_certificate = peer_certificate,
    .command = (const gchar * const *) command
  };
  g_signal_connect (socket_client, "event", G_CALLBACK (client_on_socket_client_event), &self);

  g_debug ("Attempting connection to %s/%u", host, port);

  /* We handle the 'primary connection' connect synchronously */
  g_autoptr(GSocketConnection) primary = g_socket_client_connect (socket_client, connectable, NULL, error);
  if (primary == NULL)
    return FALSE;

  g_debug ("Successfully connected.");

  self.primary = g_io_stream_get_input_stream (G_IO_STREAM (primary));
  g_input_stream_read_bytes_async (self.primary, 1, G_PRIORITY_DEFAULT, NULL, client_primary_read_ready, &self);

  g_debug ("Entering client main loop");

  while (!self.should_exit)
    g_main_context_iteration (NULL, TRUE);

  g_debug ("Exiting client main loop");

  return TRUE;
}

/* {{{1 main() */

gboolean
gmain (int argc,
       char **argv,
       GError **error)
{
  g_autofree gchar *key_file = NULL;
  g_autofree gchar *cert_file = NULL;
  g_autofree gchar *peer_cert = NULL;
  g_auto(GStrv) subv = NULL;

  g_autoptr(GOptionContext) context = g_option_context_new ("COMMAND ...");
  g_option_context_set_strict_posix (context, TRUE);
  g_option_context_add_main_entries (context, (GOptionEntry[]) {
      { "key", '\0', 0, G_OPTION_ARG_STRING, &key_file, "Key", "FILE" },
      { "cert", '\0', 0, G_OPTION_ARG_STRING, &cert_file, "Certificate", "FILE" },
      { "peer-cert", '\0', 0, G_OPTION_ARG_STRING, &peer_cert, "Peer certificate", "FILE" },
      { G_OPTION_REMAINING, '\0', 0, G_OPTION_ARG_STRING_ARRAY, &subv },
      { NULL } }, NULL);
  if (!g_option_context_parse (context, &argc, &argv, error))
    return FALSE;

  if (!subv || !subv[0] || !subv[0][0])
    return throw (error, "Required subcommand: server, client");

  if (!key_file || !cert_file || !peer_cert)
    return throw (error, "All of --key-file, --cert-file, and --peer-cert are required");

  g_autoptr(GTlsCertificate) certificate = g_tls_certificate_new_from_files (cert_file, key_file, error);
  if (!certificate)
    return FALSE;

  g_autoptr(GTlsCertificate) peer_certificate = g_tls_certificate_new_from_file (peer_cert, error);
  if (!peer_certificate)
    return FALSE;

  g_autofree gchar *subcommand = g_steal_pointer (&subv[0]);
  subv[0] = g_strdup_printf ("%s %s", argv[0], subcommand);
  g_set_prgname (subv[0]); /* for --help */

  if (g_str_equal (subcommand, "server"))
    return server (subv, certificate, peer_certificate, error);
  else if (g_str_equal (subcommand, "client"))
    return client (subv, certificate, peer_certificate, error);

  return throw (error, "Unrecognised subcommand %s", subcommand);
}

int
main (int argc, char **argv)
{
  g_autoptr(GError) error = NULL;

  setlocale (LC_ALL, "");

  gboolean success = gmain (argc, argv, &error);

  if (error)
    g_printerr ("%s: %s", argv[0], error->message);

  return success ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* {{{1 Epilogue */
/* vim:set foldmethod=marker: */
