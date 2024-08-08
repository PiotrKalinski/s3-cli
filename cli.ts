import * as AWS from 'aws-sdk';
import * as yargs from 'yargs';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as readlineSync from 'readline-sync';

const encryptedConfigFilePath = path.join(__dirname, 'aws-config.enc');

// Encryption and Decryption functions
function encrypt(text: string, password: string): string {
    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text: string, password: string): string {
    const [ivHex, encrypted] = text.split(':');
    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function loadEncryptedAWSConfig(password: string) {
    if (fs.existsSync(encryptedConfigFilePath)) {
        const encryptedConfig = fs.readFileSync(encryptedConfigFilePath, 'utf-8');
        const config = JSON.parse(decrypt(encryptedConfig, password));
        console.log('Decrypted AWS Config:', {
            accessKeyId: config.accessKeyId.replace(/(.{4})(.*)(.{4})/, '$1*************$3'), // Masking
            secretAccessKey: config.secretAccessKey.replace(/(.{4})(.*)(.{4})/, '$1**************************$3'), // Masking
            region: config.region
        }); // Debug log

        return config;  
    } else {
        console.error('Encrypted AWS configuration file not found. Please run "configure" command first.');
        process.exit(1);
    }
}

function saveEncryptedAWSConfig(config: { accessKeyId: string, secretAccessKey: string, region: string }, password: string) {
    const encryptedConfig = encrypt(JSON.stringify(config), password);
    fs.writeFileSync(encryptedConfigFilePath, encryptedConfig);
    AWS.config.update(config);
}




yargs
    .command('configure', 'Configure AWS credentials', {}, async () => {  
        const accessKeyId = readlineSync.question('Enter Access Key ID: '); 
        const secretAccessKey = readlineSync.question('Enter Secret Access Key: ', { hideEchoBack: true }); 
        const region = readlineSync.question('Enter AWS Region: '); 
        const password = readlineSync.question('Password: ', { hideEchoBack: true });
        saveEncryptedAWSConfig({ accessKeyId, secretAccessKey, region }, password);
        console.log('AWS configuration saved successfully.'); 
    })
    .command('list', 'List all files in the S3 bucket', {}, async () => {
        const password = readlineSync.question('Password: ', { hideEchoBack: true });

        const encryptedConfig = loadEncryptedAWSConfig(password);

        AWS.config.update({
            accessKeyId: encryptedConfig.accessKeyId,
            secretAccessKey: encryptedConfig.secretAccessKey,
            region: encryptedConfig.region
        });

                
        const s3 = new AWS.S3();
        const bucketName = 'developer-task';
        const prefix = 'a-wing/';
        

        try {
            const data = await s3.listObjectsV2({ Bucket: bucketName, Prefix: prefix }).promise();
            data.Contents?.forEach(file => console.log(file.Key));
        } catch (err) {
            console.error('Error listing files:', err);
        }
    })
    .command('upload <filePath>', 'Upload a local file to the S3 bucket', (yargs) => {
        return yargs
            .positional('filePath', { type: 'string', demandOption: true });
    }, async (argv: yargs.ArgumentsCamelCase<{ filePath: string }>) => {
        const { filePath } = argv;
        const newFileName = readlineSync.question('Enter new file name for S3: ');
        const password = readlineSync.question('Password: ', { hideEchoBack: true });
        const encryptedConfig = loadEncryptedAWSConfig(password);

        AWS.config.update({
            accessKeyId: encryptedConfig.accessKeyId,
            secretAccessKey: encryptedConfig.secretAccessKey,
            region: encryptedConfig.region
        });

        const s3 = new AWS.S3();
        const bucketName = 'developer-task';
        const prefix = 'a-wing/';
        try {
            const fileContent = fs.readFileSync(filePath);
            await s3.putObject({
                Bucket: bucketName,
                Key: `${prefix}${newFileName}`,
                Body: fileContent
            }).promise();
            console.log(`File uploaded successfully to ${prefix}${newFileName}`);
        } catch (err) {
            console.error('Error uploading file:', err);
        }
    })
    .command('filter', 'List files in the S3 bucket that match the regex', {}, async () => { 
        const filter = readlineSync.question('Enter regex filter: '); 
        const password = readlineSync.question('Password: ', { hideEchoBack: true });
        const encryptedConfig = loadEncryptedAWSConfig(password);

        AWS.config.update({
            accessKeyId: encryptedConfig.accessKeyId,
            secretAccessKey: encryptedConfig.secretAccessKey,
            region: encryptedConfig.region
        });

        const s3 = new AWS.S3();
        const bucketName = 'developer-task';
        const prefix = 'a-wing/';
        const regex = new RegExp(filter); // Create regex from user input
        try {
            const data = await s3.listObjectsV2({ Bucket: bucketName, Prefix: prefix }).promise();
            data.Contents?.filter(file => regex.test(file.Key!)).forEach(file => console.log(file.Key));
        } catch (err) {
            console.error('Error filtering files:', err);
        }
    })
    .command('delete', 'Delete files in the S3 bucket that match the regex', {}, async () => { 
        const regex = readlineSync.question('Enter regex filter: '); 
        const password = readlineSync.question('Password: ', { hideEchoBack: true });
        const encryptedConfig = loadEncryptedAWSConfig(password);

        AWS.config.update({
            accessKeyId: encryptedConfig.accessKeyId,
            secretAccessKey: encryptedConfig.secretAccessKey,
            region: encryptedConfig.region
        });

        const s3 = new AWS.S3();
        const bucketName = 'developer-task';
        const prefix = 'a-wing/';
        
        const filter = new RegExp(regex); 
        try {
            const data = await s3.listObjectsV2({ Bucket: bucketName, Prefix: prefix }).promise();
            const filesToDelete = data.Contents?.filter(file => filter.test(file.Key!)).map(file => ({ Key: file.Key! }));
            if (filesToDelete && filesToDelete.length > 0) {
                await s3.deleteObjects({
                    Bucket: bucketName,
                    Delete: { Objects: filesToDelete }
                }).promise();
                console.log('Files deleted successfully');
            } else {
                console.log('No files matched the regex');
            }
        } catch (err) {
            console.error('Error deleting files:', err);
        }
    })
    .demandCommand(1, 'You need at least one command before moving on')
    .help()
    .argv;