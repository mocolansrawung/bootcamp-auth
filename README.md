# My Go Project

This project is a web application written in Go. It follows a clean architecture pattern and uses JWT for authentication. It's an bootcamp auth microservices with a broad features to implement

## Prerequisites

Make sure you have Go installed on your machine. You can download it from the official [Go website](https://golang.org/dl/).

You will also need to install make. You can download it from the official [GNU Make website](https://www.gnu.org/software/make/).

## Installation

Follow these steps to get the project up and running:

1. Clone the repository to your local machine.

git clone https://github.com/mocolansrawung/bootcamp-auth.git
cd repo


2. Install the Go module dependencies.

go mod tidy


3. Setup your environment variables. Copy the example `.env.example` file to a new file named `.env` and replace the placeholder values with your actual values.


4. Run the application. The `make run` command will start the server.

make run


Now, you can access the web application at http://localhost:8080 (or whichever port you specified in your .env file).


Major Improvements:
1. fixing validate auth handler to be cleaner and get rid of service parsing function
2. destructure jwt service to be cleaner, reuse, and maintainable.
3. fixing the response logic by returning access token for both register and login endpoint