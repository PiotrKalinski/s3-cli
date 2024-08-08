# S3 CLI Tool

## Overview

This project is a command-line interface (CLI) tool for managing AWS S3 buckets. It allows users to configure AWS credentials, list files in a bucket, upload files, filter files based on regex, and delete files from the bucket.

## Features

- **Configure AWS Credentials**: Securely save AWS credentials in an encrypted format.
- **List Files**: Retrieve and display all files in a specified S3 bucket.
- **Upload Files**: Upload local files to the S3 bucket.
- **Filter Files**: List files that match a specified regex pattern.
- **Delete Files**: Remove files from the S3 bucket that match a regex pattern.

## Commands

### Configure

Prompts for AWS Access Key ID, Secret Access Key, Region, and a password to encrypt the credentials.

### List

Lists all files in the specified S3 bucket.

### Upload

Uploads a specified local file to the S3 bucket. Prompts for the S3 key.

### Filter

Lists files in the S3 bucket that match a user-defined regex pattern.

### Delete

Deletes files in the S3 bucket that match a user-defined regex pattern.

## Dependencies

- `aws-sdk`: For interacting with AWS services.
- `yargs`: For command-line argument parsing.
- `readline-sync`: For synchronous user input.
- `crypto`: For encryption and decryption of credentials.

## License

This project is licensed under the ISC License.