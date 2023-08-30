#include "tx_api.h"
#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "nx_secure_x509.h"

/* Define the size of our application stack. */
#define DEMO_STACK_SIZE 4096

/* Define the remote server IP address using NetX IP_ADDRESS macro. */
#define REMOTE_SERVER_IP_ADDRESS IP_ADDRESS(192, 168, 1, 2)

/* Define the IP address for this device. */
#define DEVICE_IP_ADDRESS IP_ADDRESS(192, 168, 1, 3)

/* Define the remote server port. 443 is the HTTPS default. */
#define REMOTE_SERVER_PORT 443

/***** Substitute your ethernet driver entry function here *********/
extern VOID _nx_linux_network_driver(NX_IP_DRIVER *);

/* Define the ThreadX and NetX object control blocks...  */

NX_PACKET_POOL pool_0;
NX_IP ip_0;
NX_TCP_SOCKET tcp_socket;
NX_SECURE_TLS_SESSION tls_session;
NX_SECURE_X509_CERT certificate;

/* Define an HTTP request to be sent to the HTTPS web server not defined here but
  represented by the ellipsis. */
UCHAR http_request[] = {"GET /example.html HTTP/1.1"};

/* Define the IP thread's stack area.  */
ULONG ip_thread_stack[3 * 1024 / sizeof(ULONG)];

/* Define packet pool for the demonstration.  */
#define NX_PACKET_POOL_SIZE ((1536 + sizeof(NX_PACKET)) * 32)

ULONG packet_pool_area[NX_PACKET_POOL_SIZE / sizeof(ULONG) + 64 / sizeof(ULONG)];

/* Define the ARP cache area.  */
ULONG arp_space_area[512 / sizeof(ULONG)];

/* Define the TLS Client thread.  */
ULONG tls_client_thread_stack[6 * 1024 / sizeof(ULONG)];
TX_THREAD tls_client_thread;
void client_thread_entry(ULONG thread_input);

/* Define the TLS packet reassembly buffer. */
UCHAR tls_packet_buffer[18000];

/* Define the metadata area for TLS cryptography. The actual size needed can be
   Ascertained by calling nx_secure_tls_metadata_size_calculate.
*/
UCHAR tls_crypto_metadata[18000];

/* Pointer to the TLS ciphersuite table that is included in the platform-specific
   cryptography subdirectory. The table maps the cryptographic routines for the
   platform to function pointers usable by the TLS library.
*/
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;
extern const USHORT nx_crypto_ecc_supported_groups[];
extern const NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const UINT nx_crypto_ecc_supported_groups_size;

/* Binary data for the TLS Client X.509 trusted root CA certificate, ASN.1 DER-
   encoded. A trusted certificate must be provided for TLS Client applications
   (unless X.509 authentication is disabled) or TLS will treat all certificates as
   untrusted and the handshake will fail.
*/

/* DER-encoded binary certificate, not defined here but represented by the ellipsis,
   for the sake of brevity. */
const UCHAR trusted_ca_data[] = {
    0x30, 0x82, 0x03, 0x11, 0x30, 0x82, 0x01, 0xF9, 0x02, 0x14, 0x25, 0x1F,
    0xB0, 0xB5, 0x2A, 0xEB, 0x33, 0x30, 0x86, 0xF7, 0x64, 0x1B, 0xB2, 0x59,
    0xCD, 0x0E, 0x09, 0x4C, 0xD4, 0x27, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86,
    0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x45, 0x31,
    0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55,
    0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x53,
    0x6F, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30,
    0x1F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x18, 0x49, 0x6E, 0x74, 0x65,
    0x72, 0x6E, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73,
    0x20, 0x50, 0x74, 0x79, 0x20, 0x4C, 0x74, 0x64, 0x30, 0x1E, 0x17, 0x0D,
    0x32, 0x33, 0x30, 0x38, 0x32, 0x38, 0x30, 0x32, 0x30, 0x39, 0x31, 0x30,
    0x5A, 0x17, 0x0D, 0x33, 0x33, 0x30, 0x38, 0x32, 0x35, 0x30, 0x32, 0x30,
    0x39, 0x31, 0x30, 0x5A, 0x30, 0x45, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06,
    0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x53, 0x6F, 0x6D, 0x65, 0x2D, 0x53,
    0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x04,
    0x0A, 0x0C, 0x18, 0x49, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74, 0x20,
    0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20,
    0x4C, 0x74, 0x64, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A,
    0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82,
    0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00,
    0x9F, 0xD3, 0x50, 0xCB, 0x25, 0x74, 0xC9, 0xCB, 0xD2, 0x68, 0x07, 0x30,
    0xBF, 0x2D, 0x93, 0x08, 0x86, 0x3D, 0x82, 0x56, 0xC4, 0x28, 0x8F, 0xFD,
    0x61, 0x75, 0x29, 0xB3, 0x79, 0x62, 0xC1, 0xE9, 0xC3, 0x8E, 0xB6, 0xF6,
    0x20, 0x47, 0x34, 0x44, 0x3D, 0x41, 0x42, 0xBC, 0xC1, 0xC4, 0xAB, 0xFC,
    0x20, 0x72, 0x32, 0x67, 0x4E, 0xBC, 0x0C, 0x47, 0xD3, 0x60, 0xC1, 0x49,
    0x5A, 0x9B, 0x8D, 0x98, 0x23, 0x3C, 0x1E, 0xFD, 0x62, 0x8C, 0xB2, 0xD9,
    0xD3, 0x85, 0x22, 0xDE, 0x5B, 0xBB, 0xE4, 0x13, 0xA0, 0xD1, 0x04, 0x9F,
    0xC7, 0x3D, 0xA8, 0x5B, 0x5D, 0x1C, 0x87, 0xCC, 0xE4, 0x81, 0xF3, 0x4D,
    0x9F, 0xDD, 0x24, 0x95, 0xAE, 0xC1, 0xC0, 0xEE, 0x02, 0xAE, 0xD6, 0xB5,
    0xE2, 0xF7, 0xBD, 0x31, 0x53, 0xD9, 0xF4, 0xD4, 0x15, 0xDD, 0x2E, 0x7A,
    0x8A, 0x46, 0xEF, 0xA2, 0xE2, 0x15, 0x95, 0xAF, 0x8C, 0x10, 0x28, 0xCC,
    0x68, 0x6D, 0x57, 0x24, 0x86, 0xDC, 0xCB, 0x91, 0x33, 0xF0, 0x4A, 0xB2,
    0x77, 0xF2, 0x9C, 0x25, 0x88, 0x75, 0x7D, 0xEE, 0xEA, 0x09, 0x57, 0xFD,
    0x4E, 0x47, 0x87, 0x14, 0x24, 0x1E, 0xAE, 0x2B, 0x74, 0x0A, 0xE7, 0x42,
    0xB6, 0xEC, 0x1A, 0x35, 0x1E, 0xA2, 0x56, 0x9B, 0x83, 0xA4, 0x2E, 0xF7,
    0x02, 0x5F, 0x21, 0x68, 0x66, 0x18, 0x0E, 0x2F, 0x4D, 0xC7, 0x49, 0x87,
    0xBC, 0xC4, 0x66, 0x49, 0x96, 0x75, 0x5A, 0x75, 0xB9, 0x0A, 0xD9, 0x29,
    0x45, 0xCD, 0xD7, 0x2D, 0xD4, 0x92, 0xA7, 0xAB, 0x89, 0xE2, 0xE2, 0x41,
    0x42, 0x6C, 0xDC, 0xB6, 0x46, 0x0E, 0xCD, 0xC2, 0x7C, 0x9D, 0x03, 0x42,
    0xC1, 0x8D, 0xC8, 0xBA, 0x63, 0xF2, 0x75, 0xE2, 0xB7, 0xF3, 0xEA, 0x8C,
    0x60, 0x8D, 0x95, 0x69, 0x89, 0xCA, 0x01, 0xF9, 0x6F, 0xFB, 0xD0, 0x53,
    0x56, 0x5B, 0x66, 0xAF, 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x0D, 0x06,
    0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00,
    0x03, 0x82, 0x01, 0x01, 0x00, 0x0C, 0x23, 0x8A, 0xD3, 0xCF, 0x6B, 0x05,
    0x74, 0xB2, 0xBB, 0x2F, 0xBA, 0xC6, 0xEF, 0x85, 0x31, 0x72, 0xA1, 0x61,
    0x96, 0xD2, 0x18, 0x15, 0x38, 0xBB, 0xB9, 0x19, 0x93, 0x52, 0x88, 0xC4,
    0x6D, 0x05, 0xE3, 0x3C, 0x16, 0x4C, 0x55, 0x0C, 0xFC, 0xD3, 0xDB, 0xD5,
    0xD9, 0xF9, 0x96, 0x45, 0xC5, 0xFE, 0x4E, 0xCB, 0x8C, 0xB1, 0x02, 0xB9,
    0x96, 0x14, 0xA3, 0x13, 0x0A, 0xDF, 0xCB, 0xD3, 0x2F, 0xF6, 0xEE, 0xA5,
    0x26, 0x71, 0xE2, 0x79, 0xEE, 0x52, 0x74, 0xFF, 0x2A, 0x99, 0x56, 0x28,
    0x7B, 0xFE, 0xAE, 0x73, 0xD6, 0xAC, 0x1E, 0xFA, 0xDF, 0x2E, 0x6A, 0xE4,
    0x6D, 0x40, 0xA2, 0x7B, 0xB2, 0x0B, 0x2C, 0xF9, 0x43, 0x2F, 0x51, 0x92,
    0x10, 0x42, 0x87, 0x01, 0xAD, 0x1E, 0x14, 0xA8, 0xC9, 0xED, 0x1D, 0xEF,
    0x4B, 0x10, 0xA3, 0x13, 0x12, 0x2E, 0x55, 0xD8, 0xC6, 0xE5, 0xD8, 0x11,
    0x67, 0xE8, 0x2F, 0xB5, 0xBF, 0x1C, 0xEA, 0xEF, 0x7C, 0x17, 0xFB, 0xD2,
    0xB3, 0x73, 0x80, 0x79, 0xB6, 0x55, 0x33, 0x9A, 0x18, 0x7B, 0x8E, 0x00,
    0xA7, 0x89, 0xBA, 0x23, 0x8A, 0x28, 0xF0, 0xA8, 0x59, 0x39, 0xD2, 0x99,
    0x10, 0x7A, 0x85, 0x87, 0x8A, 0x4E, 0x6E, 0xFB, 0x5E, 0xF8, 0x7B, 0xBA,
    0x13, 0x81, 0x54, 0x35, 0x02, 0x6F, 0x5F, 0xB0, 0xCC, 0x81, 0xEE, 0xC4,
    0xDB, 0x58, 0x66, 0x02, 0x50, 0x89, 0xE4, 0xBB, 0x9F, 0x9E, 0xA0, 0xE4,
    0x38, 0x3F, 0xD2, 0x5C, 0x1B, 0x00, 0xCE, 0x28, 0xB5, 0xCB, 0xB2, 0x08,
    0x9E, 0x4E, 0xB9, 0xBA, 0x15, 0x19, 0x94, 0xDA, 0xE1, 0x67, 0x05, 0xD0,
    0x7C, 0xD4, 0x8C, 0x78, 0x46, 0x7A, 0xA8, 0x5F, 0xFD, 0x49, 0x07, 0xE4,
    0x5F, 0x84, 0x74, 0xF9, 0x11, 0x13, 0xFD, 0x09, 0x60, 0x63, 0x2A, 0x8E,
    0xF0, 0xEE, 0xB3, 0x75, 0x4F, 0xFC, 0x34, 0x47, 0x12};
const UINT trusted_ca_length = 789;

/* Define main entry point.  */
int main()
{
    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();
}

/* Define the application – initialize drivers and TCP/IP setup.
   NOTE: the variable “status” should be checked after every API call. Most error
         checking has been omitted for clarity. */
void tx_application_define(void *first_unused_memory)
{
    UINT status;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool. Check status for errors. */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,
                                   (ULONG *)(((int)packet_pool_area + 64) & ~63),
                                   NX_PACKET_POOL_SIZE);

    /* Create an IP instance for the specific target. Check status for errors. This
       call is not completely defined. Please see other demo files for proper usage
       of the nx_ip_create call. */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0",
                          DEVICE_IP_ADDRESS,
                          0xFFFFFF00UL,
                          &pool_0, _nx_linux_network_driver,
                          (UCHAR *)ip_thread_stack,
                          sizeof(ip_thread_stack),
                          1);

    /* Enable ARP and supply ARP cache memory for IP Instance 0. Check status for
       errors. */
    status = nx_arp_enable(&ip_0, (void *)arp_space_area, sizeof(arp_space_area));

    /* Enable ICMP */
    status = nx_icmp_enable(&ip_0);

    /* Enable TCP traffic. Check status for errors. */
    status = nx_tcp_enable(&ip_0);

    status = nx_ip_fragment_enable(&ip_0);

    /* Initialize the NetX Secure TLS system.  */
    nx_secure_tls_initialize();

    /* Create the TLS client thread to start handling incoming requests. */
    tx_thread_create(&tls_client_thread, "TLS Client thread", client_thread_entry, 0,
                     tls_client_thread_stack, sizeof(tls_client_thread_stack),
                     16, 16, 4, TX_AUTO_START);
    return;
}

/* Thread to handle the TLS Client instance. */
void client_thread_entry(ULONG thread_input)
{
    UINT status;
    ULONG actual_status;
    NX_PACKET *send_packet;
    NX_PACKET *receive_packet;
    UCHAR receive_buffer[100];
    ULONG bytes;
    ULONG server_ipv4_address;

    /* We are not using the thread input parameter so suppress compiler warning. */
    NX_PARAMETER_NOT_USED(thread_input);

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status,
                                NX_IP_PERIODIC_RATE);
    printf("nx_ip_status_check : %d\n", status);
    printf("nx_ip_status_check : 0x%x\n", status);

    /* Create a TCP socket to use for our TLS session.  */
    status = nx_tcp_socket_create(&ip_0, &tcp_socket, "TLS Client Socket",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                                  NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    printf("nx_tcp_socket_create : %d\n", status);
    printf("nx_tcp_socket_create : 0x%x\n", status);

    /* Create a TLS session for our socket. This sets up the TLS session object for
           later use */
    status = nx_secure_tls_session_create(&tls_session,
                                          &nx_crypto_tls_ciphers_ecc,
                                          tls_crypto_metadata,
                                          sizeof(tls_crypto_metadata));
    printf("nx_secure_tls_session_create : %d\n", status);
    printf("nx_secure_tls_session_create : 0x%x\n", status);

    /* Initialize ECC parameters for this session. */
    status = nx_secure_tls_ecc_initialize(&tls_session,
                                          nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    printf("nx_secure_tls_ecc_initialize : %d\n", status);
    printf("nx_secure_tls_ecc_initialize : 0x%x\n", status);

    /* Set the packet reassembly buffer for this TLS session. */
    status = nx_secure_tls_session_packet_buffer_set(&tls_session, tls_packet_buffer,
                                                     sizeof(tls_packet_buffer));
    printf("nx_secure_tls_session_packet_buffer_set : %d\n", status);
    printf("nx_secure_tls_session_packet_buffer_set : 0x%x\n", status);

    /* Initialize an X.509 certificate with our CA root certificate data. */
    nx_secure_x509_certificate_initialize(&certificate, trusted_ca_data,
                                          trusted_ca_length, NX_NULL, 0,
                                          NX_NULL, 0,
                                          NX_SECURE_X509_KEY_TYPE_NONE);
    printf("nx_secure_x509_certificate_initialize : %d\n", status);
    printf("nx_secure_x509_certificate_initialize : 0x%x\n", status);

    /* Add the initialized certificate as a trusted root certificate. */
    nx_secure_tls_trusted_certificate_add(&tls_session, &certificate);

    /* Bind the TCP socket to any port.  */
    status = nx_tcp_client_socket_bind(&tcp_socket, NX_ANY_PORT, NX_WAIT_FOREVER);
    printf("nx_tcp_client_socket_bind : %d\n", status);
    printf("nx_tcp_client_socket_bind : 0x%x\n", status);

    /* Setup this thread to open a connection on the TCP socket to a remote server.
       The IP address can be used directly or it can be obtained via DNS or other
       means.*/
    server_ipv4_address = REMOTE_SERVER_IP_ADDRESS;
    status = nx_tcp_client_socket_connect(&tcp_socket, server_ipv4_address,
                                          REMOTE_SERVER_PORT, NX_WAIT_FOREVER);
    printf("nx_tcp_client_socket_connect : %d\n", status);
    printf("nx_tcp_client_socket_connect : 0x%x\n", status);

    /* Start the TLS Session using the connected TCP socket. This function will
       ascertain from the TCP socket state that this is a TLS Client session. */
    status = nx_secure_tls_session_start(&tls_session, &tcp_socket,
                                         NX_WAIT_FOREVER);
    printf("nx_secure_tls_session_start : %d\n", status);
    printf("nx_secure_tls_session_start : 0x%x\n", status);

    /* Allocate a TLS packet to send an HTTP request over TLS (HTTPS). */
    status = nx_secure_tls_packet_allocate(&tls_session, &pool_0, &send_packet,
                                           NX_WAIT_FOREVER);
    printf("nx_secure_tls_packet_allocate : %d\n", status);
    printf("nx_secure_tls_packet_allocate : 0x%x\n", status);

    /* Populate the packet with our HTTP request. */
    nx_packet_data_append(send_packet, http_request, sizeof(http_request), &pool_0,
                          NX_WAIT_FOREVER);

    /* Send the HTTP request over the TLS Session, turning it into HTTPS. */
    status = nx_secure_tls_session_send(&tls_session, send_packet, NX_WAIT_FOREVER);
    printf("nx_secure_tls_session_send : %d\n", status);
    printf("nx_secure_tls_session_send : 0x%x\n", status);

    /* If the send fails, you must release the packet.  */
    if (status != NX_SUCCESS)
    {
        /* Release the packet since the packet was not sent.  */
        nx_packet_release(send_packet);
    }

    /* Receive the HTTP response and any data from the server. */
    status = nx_secure_tls_session_receive(&tls_session, &receive_packet, NX_WAIT_FOREVER);
    printf("nx_secure_tls_session_receive : %d\n", status);
    printf("nx_secure_tls_session_receive : 0x%x\n", status);

    if (status == NX_SUCCESS)
    {
        /* Extract the data we received from the remote server. */
        status = nx_packet_data_extract_offset(receive_packet, 0, receive_buffer,
                                               100, &bytes);
        /* Display the response data. */
        receive_buffer[bytes] = 0;
        printf("Received data: %s\n", receive_buffer);

        /* Release the packet when done with it. */
        nx_packet_release(receive_packet);
    }

    /* End the TLS session now that we have received our HTTPS/HTML response. */
    status = nx_secure_tls_session_end(&tls_session, NX_WAIT_FOREVER);
    printf("nx_secure_tls_session_end : %d\n", status);
    printf("nx_secure_tls_session_end : 0x%x\n", status);
    /* Check for errors to make sure the session ended cleanly. */

    /* Disconnect the TCP socket. */
    status = nx_tcp_socket_disconnect(&tcp_socket, NX_WAIT_FOREVER);
    printf("nx_tcp_socket_disconnect : %d\n", status);
    printf("nx_tcp_socket_disconnect : 0x%x\n", status);
}
