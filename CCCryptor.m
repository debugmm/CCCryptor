#import <CommonCrypto/CommonCryptor.h>
#import <Foundation/Foundation.h>
#define cryptReadSize (1024*1024*2)
//////

/**
 *  @abstract AES en/decrypt file using file stream
 *
 *  @param srcFilePath which will be en/decrypt file path
 *  @param desFilePath en/decrypt result will be write to
 *  @param key         value raw key
 *  @param iv          value initialize vector
 *  @param operation   value kCCEncrypt/kCCDecrypt
 *
 *  @discussion        compatibility AES en/decrypt
 *                     which did not consider en/decrypt large file cause memory peak.
 */
-(void)CCCryptFileUsingAESWithSrcFilePath:(NSString *)srcFilePath desFilePath:(NSString *)desFilePath key:(NSString *)key iv:(NSString *)iv operation:(CCOperation)operation{
    
    [[NSFileManager defaultManager] removeItemAtPath:desFilePath error:nil];
    [[NSFileManager defaultManager] createFileAtPath:desFilePath contents:nil attributes:nil];
    
    NSInputStream *readStream = [NSInputStream inputStreamWithFileAtPath:srcFilePath];
    NSOutputStream *writeStream=[NSOutputStream outputStreamToFileAtPath:desFilePath append:YES];
    
    //create restrict raw key and iv
    UInt8 keyP[kCCKeySizeAES256],ivP[kCCBlockSizeAES128];
    bzero(keyP, sizeof(keyP));
    bzero(ivP, sizeof(ivP));
    
    BOOL keyConvertion=[key getBytes:keyP maxLength:kCCKeySizeAES256 usedLength:NULL encoding:NSUTF8StringEncoding options:0 range:NSMakeRange(0, kCCKeySizeAES256) remainingRange:NULL];
    BOOL ivConvertion=[iv getBytes:ivP maxLength:kCCBlockSizeAES128 usedLength:NULL encoding:NSUTF8StringEncoding options:0 range:NSMakeRange(0, kCCBlockSizeAES128) remainingRange:NULL];
    
    NSLog(@"key:%s",keyP);
    NSLog(@"iv:%s",ivP);
    NSLog(@"keyState:%d",keyConvertion);
    NSLog(@"ivState:%d",ivConvertion);
    
    // Create the cryptor
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus result;
    result = CCCryptorCreate(operation,             // operation
                             kCCAlgorithmAES,       // algorithim
                             kCCOptionPKCS7Padding, // options
                             keyP,             // key
                             kCCKeySizeAES256,  // keylength
                             ivP,              // IV
                             &cryptor);        // OUT cryptorRef
    if (result != kCCSuccess || cryptor == NULL) {
        
        return;
    }
    if(!readStream || !writeStream){
        
        return;
    }
    
    /**
     @abstract    Calculate the buffer size and create the buffers.
     
     @discussion  The MAX() check isn't really necessary, but is a safety in
     since both buffers will be the same. This just guarentees the the read
     buffer will always be large enough, even during decryption.
     */
    size_t dstBufferSize = MAX(CCCryptorGetOutputLength(cryptor, // cryptor
                                                        cryptReadSize, // input length
                                                        true), // final
                               cryptReadSize);//#define cryptReadSize (1024*1024*2)
    
    NSMutableData *dstData = [NSMutableData dataWithLength:dstBufferSize];
    NSMutableData *srcData = [NSMutableData dataWithLength:cryptReadSize];
    
    uint8_t *srcBytes = srcData.mutableBytes;
    uint8_t *dstBytes = dstData.mutableBytes;
    
    // Read and write the data in blocks
    ssize_t srcLength= 0;
    size_t dstLength = 0;
    
    [writeStream open];
    [readStream open];
    
    BOOL hasMoreData=YES;
    while(hasMoreData){
        
        srcLength=[readStream read:srcBytes maxLength:cryptReadSize];
        
        if(srcLength<0){
            goto done;
        }
        
        if(srcLength==0){
            
            break;
        }
        
        result=CCCryptorUpdate(cryptor,       // cryptor
                               srcBytes,      // dataIn
                               srcLength,     // dataInLength
                               dstBytes,      // dataOut
                               dstBufferSize, // dataOutAvailable
                               &dstLength);   // dataOutMoved
        
        if(result != kCCSuccess || cryptor == NULL){
            goto done;
        }
        [writeStream write:dstBytes maxLength:dstLength];
    }
    
    if(srcLength !=0){
        
        goto done;
    }
    
    // Write the final block
    result = CCCryptorFinal(cryptor,        // cryptor
                            dstBytes,       // dataOut
                            dstBufferSize,  // dataOutAvailable
                            &dstLength);    // dataOutMoved
    if(result != kCCSuccess || cryptor == NULL){
        goto done;
    }
    [writeStream write:dstBytes maxLength:dstLength];
    
done:
    [readStream close];
    [writeStream close];
}