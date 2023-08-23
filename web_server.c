#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// function to get MIME type( media type) based on file extension
const char *get_mime_type(const char *extension)
{
   
    if (strcmp(extension, "html") == 0)
        return "text/html";
    if (strcmp(extension, "png") == 0)
        return "image/png";
    if (strcmp(extension, "pdf") == 0)
        return "application/pdf";
    if (strcmp(extension, "txt") == 0)
        return "text/plain";
    if (strcmp(extension, "php") == 0)
        return "text/html";

    return "application/octet-stream"; // default MIME type
}

// error handling

void error_400(int socket)
{
    char bad_request_resp[] = "HTTP/1.0 400 Bad Request\r\n"
                              "Server: webserver-c\r\n\r\n"
                              "400 - Bad Request.";
    int write_val = write(socket, bad_request_resp, strlen(bad_request_resp));
    printf("error_400\n");
    if (write_val < 0)
    {
        perror("error_400 write faild");
    }
}

void error_404(int socket)
{
    char not_found_resp[] = "HTTP/1.0 404 Not Found\r\n"
                            "Server: webserver-c\r\n\r\n"
                            "404 - File not found.";
    int write_val = write(socket, not_found_resp, strlen(not_found_resp));
    printf("error_404\n");
    if (write_val < 0)
    {
        perror("error_404 write faild");
    }
}

void error_500(int socket)
{
    char internal_server_error_resp[] = "HTTP/1.0 500 Internal Server Error\r\n"
                                        "Server: webserver-c\r\n\r\n"
                                        "500 - Internal Server Error.";
    int write_val = write(socket, internal_server_error_resp, strlen(internal_server_error_resp));
    printf("error_500\n");
    if (write_val < 0)
    {
        perror("error_500 write failed");
    }
}

int main()
{
    char buffer[BUFFER_SIZE];
    // setup host address and client address
    struct sockaddr_in host_addr, client_addr;
    int server_socket, client_socket;
    socklen_t host_addrlen = sizeof(host_addr);
    socklen_t client_addrlen = sizeof(client_addr);

    // create a socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        perror("Socket creation failed");
        return 1;
    }
    printf("Socket created successfully\n");

    host_addr.sin_family = AF_INET;
    host_addr.sin_port = htons(PORT);
    host_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // bind the socket to the address
    if (bind(server_socket, (struct sockaddr *)&host_addr, host_addrlen) != 0)
    {
        perror("Bind failed");
        close(server_socket);
        return 1;
    }
    printf("Socket successfully bound to address\n");

    // listen for incoming connections
    if (listen(server_socket, SOMAXCONN) != 0)
    {
        perror("Listen failed");
        close(server_socket);
        return 1;
    }
    printf("Server listening on port %d ...\n", PORT);

    for (;;)
    {
        // accept incoming connections
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addrlen);
        if (client_socket < 0)
        {
            perror("Accept failed");
            continue;
        }
        printf("---------------------------------------------\n");
        printf("Connection accepted\n");

        // get client address
        if (getpeername(client_socket, (struct sockaddr *)&client_addr, &client_addrlen) < 0)
        {
            perror("Faild to get client address");
            close(client_socket);
            continue;
        }

        // read from the socket
        int valread = read(client_socket, buffer, BUFFER_SIZE);
        if (valread < 0)
        {
            perror("Read faild");
            close(client_socket);
            continue;
        }

        // read the request
        char method[BUFFER_SIZE], uri[BUFFER_SIZE], version[BUFFER_SIZE];
        sscanf(buffer, "%s %s %s", method, uri, version);

        printf("[%s:%u] %s %s %s\n", inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port), method, version, uri);

        if (strcmp(method, "GET") != 0)
        {
            // bad request, send a 404 response
            error_400(client_socket);
            close(client_socket);
            continue;
        }

        if (strcmp(uri, "/") == 0)
        {
            strcpy(uri, "/index.html");
        }

        // open and send the requested file
        char file_path[BUFFER_SIZE];
        snprintf(file_path, sizeof(file_path), "./files/%s", uri + 1); // uri + 1 ---> to remove leading '/'
        FILE *file = fopen(file_path, "rb");

        if (file)
        {
            // determine MIME type (media type) based on file extension
            const char *file_extension = strrchr(file_path, '.'); // tes.gdc.t.pdf
            const char *mime_type = get_mime_type(file_extension + 1);

            // create HTTP response headers
            char headers[BUFFER_SIZE];
            int headers_length = snprintf(headers, sizeof(headers),
                                          "HTTP/1.0 200 OK\r\n"
                                          "Server: webserver-c\r\n"
                                          "Content-type: %s\r\n\r\n",
                                          mime_type);

            // send response headers
            write(client_socket, headers, headers_length);
     
            // send file content
            if (file_extension && strcmp(file_extension + 1, "php") == 0)
            {
                
                // requested file is a PHP file
                // execute PHP code and capture output
                char php_cmd[BUFFER_SIZE];
                snprintf(php_cmd, sizeof(php_cmd), "php -f ./files/%s", uri + 1);
                
                FILE *php_output = popen(php_cmd, "r");

                if (php_output)
                {
                    // read and send PHP output to client
                    size_t bytes_read;
                    while ((bytes_read = fread(buffer, 1, sizeof(buffer), php_output)) > 0)
                    {
                        
                        int valwrite = write(client_socket, buffer, bytes_read);
                        if (valwrite < 0)
                        {
                            perror("Write failed");
                            break;
                        }
                    }
                    pclose(php_output);
                    
                }
                else
                {
                    // PHP execution failed
                    error_500(client_socket);
                    close(client_socket);
                    continue;
                }
                
            }
            else
            {
                // other file handling
                size_t bytes_read;
                while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
                {
                    int valwrite = write(client_socket, buffer, bytes_read);
                    if (valwrite < 0)
                    {
                        perror("Write failed");
                        break;
                    }
                }
                fclose(file);
            }
        }
        else
        {
            // file not found, send a 404 response
            error_404(client_socket);
        }

        close(client_socket);
    }

    close(server_socket);

    return 0;
}
