/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//  GPXMPPStream.m
//  GPXMPP
//
//  Created by Dalton Cherry on 9/8/12.
//  Copyright (c) 2012 Basement Krew. All rights reserved.
//
/////////////////////////////////////////////////////////////////////////////////////////////////////////////

#import "GPXMPPStream.h"

@implementation GPXMPPStream

static GPXMPPStream* globalStream;
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//returns a static stream object.
+(GPXMPPStream*)sharedStream
{
    if(!globalStream)
        globalStream = [[GPXMPPStream alloc] init];
    return globalStream;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
@synthesize port,host,server,userName,password,userJID,XMPPUsers,XMPPRooms;
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(id)init
{
    if(self = [super init])
    {
        self.port = 5222;
    }
    return self;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)connect
{
    if(!socketConnection.isConnected)
        [self performSelectorInBackground:@selector(startBackgroundStream) withObject:nil];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)writeElement:(XMLElement*)element
{
    //NSString* data = [element convertToString];
    //NSLog(@"write to Stream: %@",data);
    [socketConnection writeString:[element convertToString]];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(XMLElement*)readElement
{
    NSString* response = [socketConnection readString];
    XMLElement* element = [response XMLObjectFromString];
    NSInteger retryCount = 0;
    while(!element)
    {
        usleep(10000);
        NSString* chunk = [socketConnection readStringChunk:4096];
        if(chunk)
        {
            if(!response)
                response = chunk;
            else
                response = [response stringByAppendingString:chunk];
        }
        else
        {
            if(retryCount == 5)
                break;
            retryCount++;
        }
        element = [response XMLObjectFromString];
    }
    [socketConnection dequeueWrite];
    return element;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)startBackgroundStream
{
    NSString* hostAddress = self.server;
    if(!hostAddress && self.host)
        hostAddress = self.host;
    if(!socketConnection)
        socketConnection = [[GPSocket alloc] init];
    socketConnection.portNumber = port;
    //socketConnection.isSecureEnabled = YES;
    socketConnection.hostname = hostAddress;
    //socketConnection.timeout = 30;
    //socketConnection.timeout = 2;
    socketConnection.timeout = 1;
    //socketConnection.keepAlive = YES;
    //socketConnection.timeout = 5;
    [socketConnection connect];
    [socketConnection writeString:@"<?xml version='1.0'?>" useQueue:NO];
    XMLElement* rootElement = [self mainElement];
    //NSLog(@"main response: %@",[rootElement convertToString]);
    //XMLElement* rootElement = [response XMLObjectFromString];
    //NSLog(@"rootElement.name: %@",rootElement.name);
    if([rootElement.name isEqualToString:@"stream:stream"])
    {
        XMLElement* features = [rootElement findElement:@"stream:features"];
        while(![features.name isEqualToString:@"stream:features"])
        {
            rootElement = [self mainElement];
            //rootElement = [response XMLObjectFromString];
            features = [rootElement findElement:@"stream:features"];
        }
        XMLElement* tls = [features findElement:@"starttls"];
        //NSLog(@"features.name: %@",features.name);
        //check out TLS
        if(tls)
        {
            //NSLog(@"tls ready");
            [socketConnection writeString:@"<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>"];
            XMLElement* proceedElement = [self readElement];
            //NSLog(@"proceed: %@",proceed);
            if(proceedElement)
                socketConnection.isSecureEnabled = YES;
        }
        [self mainElement];
        //NSLog(@"response 2:%@",response);
        if([self handleAuthenication:[features findElements:@"mechanism"]])
        {
            [self resourceBind];
            [self performSelectorOnMainThread:@selector(didConnect) withObject:nil waitUntilDone:NO];
            [self fetchRoster];
            [self readLoop];
        }
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//write the main element string and get the response
-(XMLElement*)mainElement
{
    [socketConnection writeString:[NSString stringWithFormat:@"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' to='%@'>",self.host]];
    return [self readElement];//[socketConnection readString];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//gets an array of supported authenication mechanisms. Can be subclassed to allow other auth types
-(BOOL)handleAuthenication:(NSArray*)mechanisms
{
    BOOL doesMD5 = NO;
    for(XMLElement* element in mechanisms)
        if([element.text rangeOfString:@"DIGEST-MD5"].location != NSNotFound)
            doesMD5 = YES;
    if(doesMD5)
       return [self md5Auth];
    else
       return [self saslAuth];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(BOOL)saslAuth
{
    NSString *payload = [NSString stringWithFormat:@"%C%@%C%@", 0, userName, 0, password];
    XMLElement* element = [XMLElement elementWithName:@"auth" attributes:[NSDictionary dictionaryWithObjectsAndKeys:@"PLAIN",@"mechanism",@"urn:ietf:params:xml:ns:xmpp-sasl",@"xmlns", nil]];
    element.text = [GPXMPPStream base64forData:[payload dataUsingEncoding:NSUTF8StringEncoding]];;
    [self writeElement:element];
    //<auth mechanism="PLAIN" xmlns="urn:ietf:params:xml:ns:xmpp-sasl">AGRhbHRvbmlhbQBMU2dlbWVsb3Mx</auth>
    //<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="PLAIN">AGRhbHRvbmlhbQBMU0dlbWVsb3Mx</auth>
    //[socketConnection writeString:@"<auth xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\" mechanism=\"PLAIN\">AGRhbHRvbmlhbQBMU0dlbWVsb3Mx</auth>"];
    XMLElement* responseElement = [self readElement];
    while([responseElement.name isEqualToString:@"stream:features"])
    {
        [self writeElement:element];
        responseElement = [self readElement];
    }
    //NSLog(@"auth response:%@",response);
    if([responseElement.name isEqualToString:@"success"])
        return YES;
    return NO;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(BOOL)md5Auth
{
    //do MD5 authenication, just doing sasl for temp fix
    return [self saslAuth];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)resourceBind
{
    [self mainElement];
    //NSLog(@"resource response: %@",response);
    [socketConnection writeString:[NSString stringWithFormat:@"<iq type=\"set\"><bind xmlns=\"urn:ietf:params:xml:ns:xmpp-bind\"><resource>gpxmpp</resource></bind></iq>"]];
    XMLElement* bindElement = [self readElement];
    //NSLog(@"bind response: %@",response);
    XMLElement* jidElement = [bindElement findElement:@"jid"];
    self.userJID = [jidElement.text stripXMLTags];
    NSLog(@"userJID is: %@",self.userJID);
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)didConnect
{
    if([self.delegate respondsToSelector:@selector(streamDidConnect)])
        [self.delegate streamDidConnect];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//simple fetching/writing to stream
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)fetchRoster
{
    [socketConnection writeString:@"<iq type=\"get\"><query xmlns=\"jabber:iq:roster\"/></iq>"];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)fetchVCard:(NSString*)jidString
{
    [socketConnection writeString:[NSString stringWithFormat:@"<iq type=\"get\" to=\"%@\"><vCard xmlns=\"vcard-temp\"/></iq>",jidString]];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)sendMessage:(NSString*)message JID:(NSString*)jidString
{
    NSString* type = @"chat";
    GPXMPPUser* user = [self roomForJID:jidString];
    if(user)
        type = @"groupchat";
    [socketConnection writeString:[NSString stringWithFormat:@"<message to=\"%@\" from=\"%@\" type=\"%@\" xml:lang=\"en\"><body>%@</body></message>",jidString,self.userJID,type,message]];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)fetchBookmarks
{
    [socketConnection writeString:[NSString stringWithFormat:@"<iq from='%@' type=\"get\"><query xmlns=\"jabber:iq:private\"><storage xmlns=\"storage:bookmarks\"></storage></query></iq>",self.userJID]];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//process the responses of the writing/fetching above. This is done by checking the looping to check the stream for content
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)readLoop
{
    while (true)
    {
        XMLElement* element = [self readElement];
        if(element) //[element isValid])
            [self processResponses:element];
        else
            [socketConnection writeString:@" " useQueue:NO];
        
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//process all responses and push to correct delegte on main thread
-(void)processResponses:(XMLElement*)element
{
    //NSLog(@"process response: %@",[element convertToString]);
    //XMLElement* element = [response XMLObjectFromString];
    if(element)
    {
        XMLElement* queryElement = [element findElement:@"query"];
        if([element findElement:@"vcard"])
            [self processVCardResponse:element];
        else if([element findElement:@"message"])
            [self processMessageResponse:element];
        else if(queryElement && [[queryElement.attributes objectForKey:@"xmlns"] rangeOfString:@"iq:roster"].location != NSNotFound)
            [self processRosterResponse:element];
        else if([element findElement:@"conference"])
            [self processConferenceResponse:element];
        else
            [self performSelectorOnMainThread:@selector(elementDelegate:) withObject:element waitUntilDone:NO];
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//send roster response
-(void)processRosterResponse:(XMLElement*)element
{
    NSArray* items = [element findElements:@"item"];
    if(!self.XMPPUsers)
        self.XMPPUsers = [NSMutableArray arrayWithCapacity:items.count];
    for(XMLElement* rosterElement in items)
    {
        GPXMPPUser* jid = [self userForJID:[rosterElement.attributes objectForKey:@"jid"]];
        if(!jid)
        {
            jid = [GPXMPPUser createUser:[rosterElement.attributes objectForKey:@"jid"] name:[rosterElement.attributes objectForKey:@"name"]];
            [self.XMPPUsers addObject:jid];
            [self fetchVCard:jid.JID];
        }
        else
        {
            jid.JID = [rosterElement.attributes objectForKey:@"jid"];
            jid.name = [rosterElement.attributes objectForKey:@"name"];
        }
    }
    [self performSelectorOnMainThread:@selector(rosterDelegate:) withObject:self.XMPPUsers waitUntilDone:NO];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)rosterDelegate:(NSArray*)users
{
    if([self.delegate respondsToSelector:@selector(didReceiveRoster:)])
        [self.delegate didReceiveRoster:users];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)processVCardResponse:(XMLElement*)element
{
    NSString* jid = [element.attributes objectForKey:@"from"];
    //NSLog(@"Vcard: %@",jid);
    NSString* string = [[element findElement:@"BINVAL"].text stripXMLTags];
    NSData *imageData = [string dataUsingEncoding:NSASCIIStringEncoding];
    imageData = [GPXMPPStream base64Decoded:imageData];
    GPXMPPUser* user = [self userForJID:jid];
    user.image = imageData;
    if(user)
        [self performSelectorOnMainThread:@selector(vcardDelegate:) withObject:user waitUntilDone:NO];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)vcardDelegate:(GPXMPPUser*)user
{
    if([self.delegate respondsToSelector:@selector(userDidUpdate:update:)])
        [self.delegate userDidUpdate:user update:GPUserVcard];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)processMessageResponse:(XMLElement*)element
{
    //NSLog(@"got a message response: %@",[element convertToString]);
    XMLElement* body = [element findElement:@"body"];
    NSString* jidUser = [element.attributes objectForKey:@"from"];
    NSString* bareJID = jidUser;
    NSRange range = [bareJID rangeOfString:@"/"];
    if(range.location != NSNotFound)
        bareJID = [bareJID substringToIndex:range.location];
    GPXMPPUser* user = [self userForJID:jidUser];
    if(body && ![jidUser isEqualToString:self.userJID])
    {
        NSDictionary* dict = [NSDictionary dictionaryWithObjectsAndKeys:[body.text stripXMLTags],@"message",user,@"user", nil];
        [self performSelectorOnMainThread:@selector(messageDelegate:) withObject:dict waitUntilDone:NO];
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)messageDelegate:(NSDictionary*)dict
{
    NSString* message = [dict objectForKey:@"message"];
    GPXMPPUser* user = [dict objectForKey:@"user"];
    if([self.delegate respondsToSelector:@selector(didReceiveMessage:user:)])
        [self.delegate didReceiveMessage:message user:user];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)elementDelegate:(XMLElement*)element
{
    if([self.delegate respondsToSelector:@selector(didReceiveElement:)])
        [self.delegate didReceiveElement:element];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(GPXMPPUser*)userForJID:(NSString*)jid
{
    for(GPXMPPUser* user in XMPPUsers)
        if([user.JID isEqualToString:jid])
            return user;
    return nil;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(GPXMPPUser*)roomForJID:(NSString*)jid
{
    for(GPXMPPUser* user in XMPPRooms)
        if([user.JID isEqualToString:jid])
            return user;
    return nil;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//group/room chat. XEP-0045
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)processConferenceResponse:(XMLElement*)element
{
     NSArray* rooms = [element findElements:@"conference"];
    for(XMLElement* child in rooms)
        [self addRoom:[child.attributes objectForKey:@"jid"] name:[child.attributes objectForKey:@"name"]];
    [self performSelectorOnMainThread:@selector(conferenceDelegate:) withObject:XMPPRooms waitUntilDone:NO];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)conferenceDelegate:(NSArray*)rooms
{
    if([self.delegate respondsToSelector:@selector(didReceiveRooms:)])
        [self.delegate didReceiveRooms:rooms];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)addRoom:(NSString*)jid name:(NSString*)nickName
{
    if(!XMPPRooms)
        XMPPRooms = [[NSMutableArray alloc] init];
    GPXMPPUser* user = [GPXMPPUser createUser:jid name:nickName];
    user.isGroup = YES;
    [XMPPRooms addObject:user];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)joinRoom:(NSString*)jid
{
    [socketConnection writeString:[NSString stringWithFormat:@"<presence to='%@/gpxmpp'><x xmlns='http://jabber.org/protocol/muc'/></presence>",jid]];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)leaveRoom:(NSString*)jid
{
    [socketConnection writeString:[NSString stringWithFormat:@"<presence type='unavailable' to='%@'/>",jid]];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//helper stuff
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
+ (NSString*)base64forData:(NSData*)theData
{
    const uint8_t* input = (const uint8_t*)[theData bytes];
    NSInteger length = [theData length];
    
    static char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    
    NSMutableData* data = [NSMutableData dataWithLength:((length + 2) / 3) * 4];
    uint8_t* output = (uint8_t*)data.mutableBytes;
    
    NSInteger i;
    for (i=0; i < length; i += 3) {
        NSInteger value = 0;
        NSInteger j;
        for (j = i; j < (i + 3); j++) {
            value <<= 8;
            
            if (j < length) {
                value |= (0xFF & input[j]);
            }
        }
        
        NSInteger theIndex = (i / 3) * 4;
        output[theIndex + 0] =                    table[(value >> 18) & 0x3F];
        output[theIndex + 1] =                    table[(value >> 12) & 0x3F];
        output[theIndex + 2] = (i + 1) < length ? table[(value >> 6)  & 0x3F] : '=';
        output[theIndex + 3] = (i + 2) < length ? table[(value >> 0)  & 0x3F] : '=';
    }
    
    return [[[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding] autorelease];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
+(NSData*)base64Decoded:(NSData*)theData
{
	const unsigned char	*bytes = [theData bytes];
	NSMutableData *result = [NSMutableData dataWithCapacity:[theData length]];
	
	unsigned long ixtext = 0;
	unsigned long lentext = [theData length];
	unsigned char ch = 0;
	unsigned char inbuf[4] = {0, 0, 0, 0};
	unsigned char outbuf[3] = {0, 0, 0};
	short i = 0, ixinbuf = 0;
	BOOL flignore = NO;
	BOOL flendtext = NO;
	
	while( YES )
	{
		if( ixtext >= lentext ) break;
		ch = bytes[ixtext++];
		flignore = NO;
		
		if( ( ch >= 'A' ) && ( ch <= 'Z' ) ) ch = ch - 'A';
		else if( ( ch >= 'a' ) && ( ch <= 'z' ) ) ch = ch - 'a' + 26;
		else if( ( ch >= '0' ) && ( ch <= '9' ) ) ch = ch - '0' + 52;
		else if( ch == '+' ) ch = 62;
		else if( ch == '=' ) flendtext = YES;
		else if( ch == '/' ) ch = 63;
		else flignore = YES;
		
		if( ! flignore )
		{
			short ctcharsinbuf = 3;
			BOOL flbreak = NO;
			
			if( flendtext )
			{
				if( ! ixinbuf ) break;
				if( ( ixinbuf == 1 ) || ( ixinbuf == 2 ) ) ctcharsinbuf = 1;
				else ctcharsinbuf = 2;
				ixinbuf = 3;
				flbreak = YES;
			}
			
			inbuf [ixinbuf++] = ch;
			
			if( ixinbuf == 4 )
			{
				ixinbuf = 0;
				outbuf [0] = ( inbuf[0] << 2 ) | ( ( inbuf[1] & 0x30) >> 4 );
				outbuf [1] = ( ( inbuf[1] & 0x0F ) << 4 ) | ( ( inbuf[2] & 0x3C ) >> 2 );
				outbuf [2] = ( ( inbuf[2] & 0x03 ) << 6 ) | ( inbuf[3] & 0x3F );
				
				for( i = 0; i < ctcharsinbuf; i++ )
					[result appendBytes:&outbuf[i] length:1];
			}
			
			if( flbreak )  break;
		}
	}
	
	return [NSData dataWithData:result];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)dealloc
{
    [XMPPUsers release];
    [XMPPRooms release];
    [socketConnection release];
    [super dealloc];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
@end


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//helper object
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
@implementation GPXMPPUser

@synthesize name,JID,image,presence;
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
+(GPXMPPUser*)createUser:(NSString*)JID name:(NSString*)name
{
    GPXMPPUser* user = [[[GPXMPPUser alloc] init] autorelease];
    user.JID = JID;
    user.name = name;
    return user;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////

@end

