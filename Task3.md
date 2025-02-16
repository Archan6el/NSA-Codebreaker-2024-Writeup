## Task 3 - How did they get in? - (Reverse Engineering, Vulnerability Research)

**Prompt 3:**

>Great work finding those files! Barry shares the files you extracted with the blue team who share it back to Aaliyah and her team. As a first step, she ran strings across all the files found and noticed a reference to a known DIB, “Guardian Armaments” She begins connecting some dots and wonders if there is a connection between the software and the hardware tokens. But what is it used for and is there a viable threat to Guardian Armaments (GA)?
>
>She knows the Malware Reverse Engineers are experts at taking software apart and figuring out what it's doing. Aaliyah reaches out to them and keeps you in the >loop. Looking at the email, you realize your friend Ceylan is touring on that team! She is on her first tour of the Computer Network Operations Development Program
>
>Barry opens up a group chat with three of you. He wants to see the outcome of the work you two have already contributed to. Ceylan shares her screen with you as she begins to reverse the software. You and Barry grab some coffee and knuckle down to help.
>
>Figure out how the APT would use this software to their benefit
>
>
>Downloads:
>
>Executable from ZFS filesystem (server)
>Retrieved from the facility, could be important? (shredded.jpg)
>
>Prompt:
>
>Enter a valid JSON that contains the (3 interesting) keys and specific values that would have been logged if you had successfully leveraged the running software. Do ALL your work in lower case.

### Solve:
Here we go, Task 3. We're finally getting to some actual rev. 

First off, let's download the `server` executable and the `shredded.jpg` image. Opening up the image first, we are met with this:

![image](https://github.com/user-attachments/assets/91396a8d-7f82-4a49-a136-312f737a121d)

Seems to be something written on shredded paper, which was crudely put back together. It looks like it reads `JASPER_0`, or it could be `JASPER_O`. We'll keep note of it for now, and move on to the `server` executable. 

Trying to run it gives us some interesting information. 

![image](https://github.com/user-attachments/assets/36f4ab79-433a-451d-954e-e403260869e8)

We learn two key things from this. First, the `server` executable seems to be using something called `rpc`, which we can deduce from the `rpc error` message. Second, the executable needs to be able to ping some kind of auth service in order to work. 

After doing some research, `rpc` is a protocol used to call remote functions. So the `server` executable is probably trying to call some kind of ping function from an auth server. Let's pop `server` into Ghidra and Binja and see what we find. I like to use both, since in some cases, Ghidra makes it easier to see some things than Binja, and vice versa. 

After Ghidra does its analysis, we find that `server` is a Go binary. Trying to find the main function, we find a whole lot of interesting functions, but among them, two `Ping` functions

![image](https://github.com/user-attachments/assets/161b0988-4d21-4eea-8b6c-39133466fa04)

However, there isn't really anything interesting there to build off of within them, but we'll keep our eye on these `main` functions. 

After some more snooping around, I stumble upon a jackpot of interesting functions each beginning with `auth`. Since the `server` executable is trying to ping what it calls an *auth* server, we're probably in the right place. Among these functions we find what looks to be a `Ping` function, or more specifically, a `PingRequest` function. 

![image](https://github.com/user-attachments/assets/91b35027-1d2e-4318-9f49-9fa36ced77d4)
![image](https://github.com/user-attachments/assets/34702a39-7b8e-4da5-808e-6b1e152fb103)

We see some sub-functions that shed light on what parameters each function is expecting. For example, for the `AuthRequest` function, there are sub-functions called `GetPassword` and `GetUsername`, which means that it probably expects a password and username as parameters

![image](https://github.com/user-attachments/assets/b5d4da74-1977-4e9b-aff9-8bab1b202d9b)

However, the most important thing for us is the `PingRequest` function, and if we take a look, it has a `GetPing` subfunction, which means it probably expects that as a parameter. 

![image](https://github.com/user-attachments/assets/0bf781f9-44fe-4fef-919c-72c4987232c6)

We can deduce the parameters for the other functions here, and we end up with 6 that we can define. So we can start trying to make the auth server now, but how?

Since the `server` executable is in Go, we'll make the auth server in Go too. Go's implementation of the `rpc` protocol is `grpc`, and [this](https://pascalallen.medium.com/how-to-build-a-grpc-server-in-go-943f337c4e05) guide was helpful in getting started. Essentially, we first need to create a `.proto` file in which we define each of our functions, as well as their request and response parameters. That should be relatively easy to do based on what we found in Ghidra. The issue however is the `package` that each `.proto` file needs. This is a little problematic because `package` needs to match on both the client and the server. 

Thankfully, using both Ghidra *and* Binja was pretty helpful here. If we go into the `auth/auth_grpc.(*authServiceClient).Ping` function we found in Ghidra on Binja, near the end we can see this function call to `PingRequest` 

![image](https://github.com/user-attachments/assets/795cf2ce-5327-4286-8b15-12c04c527f5d)

It starts with `auth_service`, which is likely our package name. 

Now we have all we need, let's create our proto file. I name mine `ping.proto` since we're trying to get the ping function to work specifically, and set my `go_package` to `/seedGeneration`, since we saw some references to `seedGeneration` in those `main` functions we found earlier. The name of your proto file and `go_package` doesn't matter though. 

```
syntax = "proto3";

package auth_service;

option go_package = "/seedGeneration";

service AuthService {
    rpc Authenticate(AuthenticateRequest) returns (AuthenticateResponse);
    rpc Logout(LogoutRequest) returns (LogoutResponse);
    rpc Ping(PingRequest) returns (PingResponse);
    rpc RefreshToken(RefreshTokenRequest) returns (RefreshTokenResponse);
    rpc RegisterOTPSeed(RegisterOTPSeedRequest) returns (RegisterOTPSeedResponse);
    rpc VerifyOTP(VerifyOTPRequest) returns (VerifyOTPResponse);
}

message AuthenticateRequest {
    // Define fields needed for authentication
    string username = 1; // User's username
    string password = 2; // User's password
}

message AuthenticateResponse {
    // Define fields for the response
    bool success = 1;        // Indicates if authentication was successful
    string message = 2;      // Optional message for additional information
}

message LogoutRequest {
    // Define fields needed for logout
}

message LogoutResponse {
    // Define fields for the response
}

message PingRequest {
    // Define fields needed for the request
    int64 ping = 1;
}

message PingResponse {
    int64 pong = 1;
}

message RefreshTokenRequest {
    // Define fields needed for refresh token
}

message RefreshTokenResponse {
    // Define fields for the response
}

message RegisterOTPSeedRequest {
    // Define fields needed for OTP seed registration
    string username = 1;
    int64 seed = 2;
}

message RegisterOTPSeedResponse {
    // Define fields for the response
    bool success = 1;
}

message VerifyOTPRequest {
    // Define fields needed for OTP verification
    string username = 1;
    int64 otp = 2;
}

message VerifyOTPResponse {
    // Define fields for the response
    bool success = 1;
    int64 token = 2;
}
```

With our `.proto` file made, we run the `protoc` command to compile it into some Go files for us to use

`protoc --go_out=. --go-grpc_out=. ping.proto`

Now let's create the auth server. In my code, I set up some sample checks for `AuthenticateRequest` and `VerifyOTP` just to see if they do anything. Most importantly, we run the server on port 50052. 

```Go
package main

import (
	"context"
	"fmt"
	"net"
	"google.golang.org/grpc"
	"server/seedGeneration" // Replace with the actual import path for your generated pb
)

type server struct {
	seedGeneration.UnimplementedAuthServiceServer
}

// Authenticate handles the Authenticate RPC method
func (s *server) Authenticate(ctx context.Context, req *seedGeneration.AuthenticateRequest) (*seedGeneration.AuthenticateResponse, error) {
	//fmt.Println("Authenticate request received:", req)
	// Simple logic for demonstration (you can replace it with real authentication logic)
	if req.Username == "testuser" && req.Password == "testpass" {
		return &seedGeneration.AuthenticateResponse{
			Success: true,
			Message: "Authentication successful",
		}, nil
	}
	return &seedGeneration.AuthenticateResponse{
		Success: true,
		Message: "Authentication failed",
	}, nil
}

// Logout handles the Logout RPC method
func (s *server) Logout(ctx context.Context, req *seedGeneration.LogoutRequest) (*seedGeneration.LogoutResponse, error) {
	fmt.Println("Logout request received:", req)
	// For now, just return a successful response
	return &seedGeneration.LogoutResponse{}, nil
}

// Ping handles the Ping RPC method
func (s *server) Ping(ctx context.Context, req *seedGeneration.PingRequest) (*seedGeneration.PingResponse, error) {
	fmt.Println("Ping request received:", req)
	// Simple logic for Pong response
	return &seedGeneration.PingResponse{Pong: req.Ping}, nil
}

// RefreshToken handles the RefreshToken RPC method
func (s *server) RefreshToken(ctx context.Context, req *seedGeneration.RefreshTokenRequest) (*seedGeneration.RefreshTokenResponse, error) {
	fmt.Println("RefreshToken request received:", req)
	// For now, just return a simple response
	return &seedGeneration.RefreshTokenResponse{}, nil
}

// RegisterOTPSeed handles the RegisterOTPSeed RPC method
func (s *server) RegisterOTPSeed(ctx context.Context, req *seedGeneration.RegisterOTPSeedRequest) (*seedGeneration.RegisterOTPSeedResponse, error) {
	//fmt.Println("RegisterOTPSeed request received:", req)
	// For now, just return a success response
	return &seedGeneration.RegisterOTPSeedResponse{
		Success: true,
	}, nil
}

// VerifyOTP handles the VerifyOTP RPC method
func (s *server) VerifyOTP(ctx context.Context, req *seedGeneration.VerifyOTPRequest) (*seedGeneration.VerifyOTPResponse, error) {
	fmt.Println("VerifyOTP request received:", req)
	// For now, just verify OTP logic (simple check)
	if req.Otp == 123456 {
		return &seedGeneration.VerifyOTPResponse{
			Success: true,
			Token:   654321, // Sample token
		}, nil
	}
	return &seedGeneration.VerifyOTPResponse{
		Success: false,
		Token:   0,
	}, nil
}

func main() {
	// Listen on port 50052
	lis, err := net.Listen("tcp", ":50052")
	if err != nil {
		fmt.Println("Failed to listen on port 50052:", err)
		return
	}

	// Create a gRPC server
	grpcServer := grpc.NewServer()

	// Register the AuthService server
	seedGeneration.RegisterAuthServiceServer(grpcServer, &server{})

	// Start the server
	fmt.Println("gRPC server started on port 50052")
	if err := grpcServer.Serve(lis); err != nil {
		fmt.Println("Failed to start server:", err)
	}
}
```

Let's run it with `go run auth_server.go`

![image](https://github.com/user-attachments/assets/ffccbf0f-df62-4354-b4cd-d150667b4034)

If we run the `server` executable again, we get a different result!

![image](https://github.com/user-attachments/assets/5dfd2069-54d2-4402-a3a5-1a240d47830b)
![image](https://github.com/user-attachments/assets/6cc20ad7-64a8-4122-ac65-d35ad6880360)
