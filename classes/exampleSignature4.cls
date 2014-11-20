public with sharing class CloudDemoV3 {
    public static String timestamp;
    public static String AWSSignature;
    public static String accessKeyId = 'abcdefghijklmnop';
    public static String ec2version = '2010-08-31';
    private static String secretAccessKey = 'Its_a_Secret ';
    public static void startInstance(String imageId) {
        HttpRequest req = new HttpRequest();

        String endpoint = 'https://ec2.amazonaws.com/';

        calculateTimeStamp();

        String request = 'AWSAccessKeyId=' + accessKeyId +
            '&Action=RunInstances' +
            '&ImageId.1=' + imageId +
            '&MaxCount=1' +
            '&MinCount=1' +
            '&SignatureMethod=HmacSHA256' +
            '&SignatureVersion=2' +
            '&Timestamp=' + EncodingUtil.urlEncode(timestamp, 'UTF-8') +
            '&Version=' + ec2version;
        generateAWSSignature('GET', 'RunInstances', request);
        endpoint += '?' +
            'AWSAccessKeyId=' + EncodingUtil.urlEncode(accessKeyId, 'UTF-8') +
            '&Action=' + EncodingUtil.urlEncode('RunInstances', 'UTF-8') +
            '&ImageId.1=' + EncodingUtil.urlEncode(imageId, 'UTF-8') +
            '&MaxCount=' + EncodingUtil.urlEncode('1', 'UTF-8') +
            '&MinCount=' + EncodingUtil.urlEncode('1', 'UTF-8') +
            '&SignatureMethod=' + EncodingUtil.urlEncode('HmacSHA256', 'UTF-8') +
            '&SignatureVersion=' + EncodingUtil.urlEncode('2', 'UTF-8') +
            '&Timestamp=' + EncodingUtil.urlEncode(timestamp, 'UTF-8') +
            '&Version=' + EncodingUtil.urlEncode(ec2version, 'UTF-8') +
            '&Signature=' + EncodingUtil.urlEncode(AWSSignature, 'UTF-8');

        req.setEndpoint(endpoint);

        req.setMethod('GET');

        String responseBody;

        Http http = new Http();

        HttpResponse res = http.send(req);

        System.debug('STATUS:' + res.getStatus());

        System.debug('STATUS_CODE:' + res.getStatusCode());
        System.debug('BODY: ' + res.getBody());
    }
    private static void calculateTimeStamp() {
        Datetime now = Datetime.now();

        //format should be like 2006-01-01T12:00:00.000Z


        timestamp = now.formatGmt('yyyy-MM-dd') + 'T' + now.formatGmt('HH:mm:ss') + '.' + now.formatGMT('SSS') + 'Z';
        System.Debug('Formatted date : ' + timestamp);
    }
    private static void generateAWSSignature(String verb, String action, String request) {
        /*
        StringToSign = HTTPVerb + "\n" +
                        ValueOfHostHeaderInLowercase + "\n" +
                        HTTPRequestURI + "\n" +         
                        CanonicalizedQueryString
<from the preceding step>
	*/
        String canonical = verb + '\n' +
            'ec2.amazonaws.com\n' +
            '/\n' +
            request;

        system.Debug('String to Sign:\n' + canonical + '\n');

        Blob bsig = Crypto.generateMac('HmacSHA256', Blob.valueOf(canonical), Blob.valueOf(secretAccessKey));

        String signature = EncodingUtil.base64Encode(bsig);

        AWSSignature = signature;


    }

}