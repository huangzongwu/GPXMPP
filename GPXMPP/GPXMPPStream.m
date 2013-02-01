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
#import "GPHTTPRequest.h"

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
@synthesize port,host,server,userName,password,userJID,XMPPUsers,XMPPRooms,streamUser,boshURL,isConnected,timeout;
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(id)init
{
    if(self = [super init])
    {
        self.port = 5222;
        self.timeout = 30;
    }
    return self;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)connect
{
    if(!self.isConnected)
    {
        if(self.boshURL)
            [self performSelectorInBackground:@selector(boshConnect) withObject:nil];
        else
        {
            if(!socketConnection.isConnected)
                [self performSelectorInBackground:@selector(startBackgroundStream) withObject:nil];
        }
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)writeElement:(XMLElement*)element
{
    //NSString* data = [element convertToString];
    //NSLog(@"write to Stream: %@",data);
    if(boshSID)
        [self sendBoshContent:[element convertToString]];
    else
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
    socketConnection.timeout = 1;
    //socketConnection.timeout = 5;
    [socketConnection connect];
    [socketConnection writeString:@"<?xml version='1.0'?>" useQueue:NO];
    XMLElement* rootElement = [self mainElement];
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
            self.isConnected = YES;
            [self resourceBind];
            [self performSelectorOnMainThread:@selector(didConnect) withObject:nil waitUntilDone:NO];
            [self fetchVCard:self.userJID];
            [self fetchRoster];
            [self fetchPresence:nil];
            [self readLoop];
        }
        
        //if we get here, something has gone wrong
        [socketConnection close];
        [socketConnection release];
        socketConnection = nil;
        if([self.delegate respondsToSelector:@selector(streamDidFailLogin)])
            [self.delegate streamDidFailLogin];
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//write the main element string and get the response
-(XMLElement*)mainElement
{
    NSString* content = [NSString stringWithFormat:@"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' to='%@'></stream:stream>",self.host];
    if(boshSID)
    {
        return [[self syncBoshRequest:nil] XMLObjectFromString];
        /*GPHTTPRequest* request = [GPHTTPRequest requestWithString:self.boshURL];
        [request setRequestType:GPHTTPRequestRawPOST];
        [request setCacheModel:GPHTTPIgnoreCache];
        [request addRequestHeader:@"text/xml; charset=utf-8" key:@"Content-Type"];
        [request addRequestHeader:self.host key:@"Host"];
        [request setTimeout:self.timeout];
        NSString* value = [NSString stringWithFormat:@"<body rid='%d' sid='%@' xmlns='http://jabber.org/protocol/httpbind' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh' xmpp:restart='true'/>",boshRID,boshSID];
        [request addPostValue:value key:@"key"];
        [request startSync];
        boshRID++;
        return [[request responseString] XMLObjectFromString];*/
    }
    else
    {
        [socketConnection writeString:content];
        return [self readElement];
    }
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
    //[NSString stringWithFormat:@"%@@%@\x00%@\x00%@",userName,self.host, userName, password];
    NSString *payload = [NSString stringWithFormat:@"%C%@%C%@", (short)0, userName, (short)0, password];
    XMLElement* element = [XMLElement elementWithName:@"auth" attributes:[NSDictionary dictionaryWithObjectsAndKeys:@"PLAIN",@"mechanism",@"urn:ietf:params:xml:ns:xmpp-sasl",@"xmlns", nil]];
    element.text = [GPXMPPStream base64forData:[payload dataUsingEncoding:NSUTF8StringEncoding]];
    //NSRange r;
    //NSString* s = element.text;
    //while ((r = [s rangeOfString:@"/\\s/" options:NSRegularExpressionSearch]).location != NSNotFound)
    //    s = [s stringByReplacingCharactersInRange:r withString:@""];
    //element.text = s;
    XMLElement* responseElement = nil;
    if(boshSID)
    {
        NSString* response = [self syncBoshRequest:[element convertToString]];
        responseElement = [response XMLObjectFromString];
    }
    else
    {
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
    }
    //NSLog(@"auth response:%@",[responseElement convertToString]);
    if([responseElement.name isEqualToString:@"success"] || [[responseElement convertToString] rangeOfString:@"success"].location != NSNotFound)
        return YES;
    return NO;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(BOOL)md5Auth
{
    /*XMLElement* element = [XMLElement elementWithName:@"auth" attributes:[NSDictionary dictionaryWithObjectsAndKeys:@"DIGEST-MD5",@"mechanism",@"urn:ietf:params:xml:ns:xmpp-sasl",@"xmlns", nil]];
    XMLElement* responseElement = nil;
    if(boshSID)
    {
        NSString* response = [self syncBoshRequest:[element convertToString]];
        responseElement = [response XMLObjectFromString];
    }*/
    //do MD5 authenication, just doing sasl for temp fix
    return [self saslAuth];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)resourceBind
{
    [self mainElement];
    //XMLElement* response = 
    //NSLog(@"resource response: %@",[response convertToString]);
    NSString* content = [NSString stringWithFormat:@"<iq id='bind_1' type=\"set\"><bind xmlns=\"urn:ietf:params:xml:ns:xmpp-bind\"><resource>gpxmpp</resource></bind></iq>"];
    XMLElement* bindElement = nil;
    if(boshSID)
    {
        NSString* response = [self syncBoshRequest:content];
        bindElement = [response XMLObjectFromString];
    }
    else
    {
        [socketConnection writeString:content];
        bindElement = [self readElement];
    }
    XMLElement* jidElement = [bindElement findElement:@"jid"];
    self.userJID = [jidElement.text stripXMLTags];
    self.streamUser = [[GPXMPPUser createUser:self.userJID name:nil] retain];
    
    NSLog(@"userJID is: %@",self.userJID);
    content = @"<iq type='set' id='session_1'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>";
    if(boshSID)
        [self syncBoshRequest:content];
    else
    {
        [socketConnection writeString:content];
        bindElement = [self readElement];
    }
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
    NSString* content = [NSString stringWithFormat:@"<iq from='%@' type='get' id='roster_1'><query xmlns='jabber:iq:roster'/></iq>",self.userJID];//@"<iq type=\"get\"><query xmlns=\"jabber:iq:roster\"/></iq>";
    if(boshSID)
        [self sendBoshContent:content];
    else
        [socketConnection writeString:content];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)fetchVCard:(NSString*)jidString
{
    NSString* jid = [self cleanJID:jidString];
    NSString* content = [NSString stringWithFormat:@"<iq type=\"get\" to=\"%@\"><vCard xmlns=\"vcard-temp\"/></iq>",jid];
    if(boshSID)
        [self sendBoshContent:content];
    else
        [socketConnection writeString:content];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)sendMessage:(NSString*)message JID:(NSString*)jidString
{
    NSString* type = @"chat";
    GPXMPPUser* user = [self roomForJID:jidString];
    if(user)
        type = @"groupchat";
    
    NSString* text = [message xmlSafe];
    //NSLog(@"safe string: %@",text);
    NSString* content = [NSString stringWithFormat:@"<message to=\"%@\" from=\"%@\" type=\"%@\" xml:lang=\"en\"><body>%@</body></message>",jidString,self.userJID,type,text];
    if(boshSID)
        [self sendBoshContent:content];
    else
        [socketConnection writeString:content];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)sendTypingState:(GPTypingState)state JID:(NSString*)jidString
{
    NSString* type = @"chat";
    GPXMPPUser* user = [self roomForJID:jidString];
    if(user)
        type = @"groupchat";
    NSString* text = nil;
    if(state == GPTypingComposing)
        text = [NSString stringWithFormat:@"<composing></composing>"];
    else
        text = [NSString stringWithFormat:@"<active></active>"];
    NSString* content = [NSString stringWithFormat:@"<message to=\"%@\" from=\"%@\" type=\"%@\" xml:lang=\"en\">%@</message>",jidString,self.userJID,type,text];
    if(boshSID)
        [self sendBoshContent:content];
    else
        [socketConnection writeString:content];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)fetchPresence:(NSString*)jidString
{
    NSString* content = nil;
    if(!jidString)
        content = @"<presence/>";
    else
        content = [NSString stringWithFormat:@"<presence to=\"%@\" from=\"%@\" type='probe'></presence>",jidString,self.userJID]; //subscribe, I might need to use this
    if(boshSID)
        [self sendBoshContent:content];
    else
        [socketConnection writeString:content];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)fetchBookmarks
{
    NSString* content = [NSString stringWithFormat:@"<iq from='%@' type=\"get\"><query xmlns=\"jabber:iq:private\"><storage xmlns=\"storage:bookmarks\"></storage></query></iq>",self.userJID];
    if(boshSID)
        [self sendBoshContent:content];
    else
        [socketConnection writeString:content];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//process the responses of the writing/fetching above. This is done by checking the looping to check the stream for content
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)readLoop
{
    while (true)
    {
        XMLElement* element = [self readElement];
        if(element)
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
    if(boshSID)
    {
        XMLElement* body = [element findElement:@"body"];
        if(body.childern.count > 0)
            element = [element.childern objectAtIndex:0];
        else if([body.text isEqualToString:@" "] || [body.text isEqualToString:@""])
        {
            element = nil;
        }
    }
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
        else if([element findElement:@"presence"])
            [self processPresence:element];
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
            [self fetchPresence:jid.JID];
        }
        else
        {
            jid.JID = [rosterElement.attributes objectForKey:@"jid"];
            jid.name = [rosterElement.attributes objectForKey:@"name"];
        }
    }
    [self performSelectorOnMainThread:@selector(rosterDelegate:) withObject:self.XMPPUsers waitUntilDone:NO];
    [self performSelector:@selector(refetchPresence) withObject:nil afterDelay:1];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)refetchPresence
{
    for(GPXMPPUser* user in self.XMPPUsers)
        [self fetchPresence:user.JID];
    [self performSelectorOnMainThread:@selector(refetchPresenceDelegate) withObject:nil waitUntilDone:NO];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)refetchPresenceDelegate
{
    if([self.delegate respondsToSelector:@selector(didReloadPresence)])
        [self.delegate didReloadPresence];
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
    NSString* name = [element findElement:@"FN"].text;
    NSRange range = [name rangeOfString:@"<"];
    if(range.location != NSNotFound)
        name = [name substringToIndex:range.location];
    if(!jid)
        jid = self.userJID;
    NSString* string = [[element findElement:@"BINVAL"].text stripXMLTags];
    NSData *imageData = nil;
    if(string)
    {
        imageData = [string dataUsingEncoding:NSASCIIStringEncoding];
        imageData = [GPXMPPStream base64Decoded:imageData];
    }
    GPXMPPUser* user = [self userForJID:jid];
    if(!user)
        user = [self roomUserForJID:jid room:nil];
    if(user)
    {
        user.image = imageData;
        if(name)
            user.name = name;
        if(user)
            [self performSelectorOnMainThread:@selector(vcardDelegate:) withObject:user waitUntilDone:NO];
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)vcardDelegate:(GPXMPPUser*)user
{
    if([self.delegate respondsToSelector:@selector(userDidUpdate:update:)])
        [self.delegate userDidUpdate:user update:GPUserTypeVcard];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)processMessageResponse:(XMLElement*)element
{
    //NSLog(@"got a message response: %@",[element convertToString]);
    NSString* type = [element.attributes objectForKey:@"type"];
    XMLElement* body = [element findElement:@"body"];
    NSString* jidUser = [element.attributes objectForKey:@"from"];
    NSString* bareJID = jidUser;
    NSRange range = [bareJID rangeOfString:@"/"];
    GPXMPPUser* realUser = nil;
    if(range.location != NSNotFound)
        bareJID = [bareJID substringToIndex:range.location];
    GPXMPPUser* user = [self userForJID:bareJID];
    if(!user)
        user = [self roomForJID:bareJID];
    if(range.location != NSNotFound && [type isEqualToString:@"groupchat"])
    {
        NSString* name = [jidUser substringFromIndex:range.location+1];
        name = [NSString stringWithFormat:@"%@@%@",name,host];
        realUser = [self roomUserForJID:name room:user];
        if([[self cleanJID:realUser.JID] isEqualToString:[self cleanJID:self.userJID]] || !realUser)
            return;
    }
    if(!body)
    {
        GPTypingState state = GPTypingActive;
        XMLElement* compose = [element findElement:@"composing"];
        if(compose)
            state = GPTypingComposing;
        //compose = [element findElement:@"active"];
        //if(compose)
        //    NSLog(@"active!");
        NSDictionary* dict = nil;
        if(realUser)
            dict = [NSDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:state],@"state",user,@"user",realUser,@"realUser", nil];
        else
            dict = [NSDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:state],@"state",user,@"user", nil];
        [self performSelectorOnMainThread:@selector(composingDelegate:) withObject:dict waitUntilDone:NO];
        return;
        
    }
    if(body && ![jidUser isEqualToString:self.userJID])
    {
        NSDictionary* dict = nil;
        if(realUser)
            dict = [NSDictionary dictionaryWithObjectsAndKeys:[body.text stripXMLTags],@"message",user,@"user",realUser,@"realUser", nil];
        else
            dict = [NSDictionary dictionaryWithObjectsAndKeys:[body.text stripXMLTags],@"message",user,@"user", nil];
        [self performSelectorOnMainThread:@selector(messageDelegate:) withObject:dict waitUntilDone:NO];
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)messageDelegate:(NSDictionary*)dict
{
    NSString* message = [dict objectForKey:@"message"];
    GPXMPPUser* user = [dict objectForKey:@"user"];
    GPXMPPUser* realUser = [dict objectForKey:@"realUser"];
    if(realUser)
    {
        if([self.delegate respondsToSelector:@selector(didReceiveGroupMessage:room:user:)])
            [self.delegate didReceiveGroupMessage:message room:user user:realUser];
    }
    else if([self.delegate respondsToSelector:@selector(didReceiveMessage:user:)])
        [self.delegate didReceiveMessage:message user:user];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)composingDelegate:(NSDictionary*)dict
{
    NSNumber* state = [dict objectForKey:@"state"];
    GPXMPPUser* user = [dict objectForKey:@"user"];
    GPXMPPUser* realUser = [dict objectForKey:@"realUser"];
    if(realUser)
    {
        if([self.delegate respondsToSelector:@selector(didReceiveGroupComposingState:room:user:)])
            [self.delegate didReceiveGroupComposingState:[state intValue] room:user user:realUser];
    }
    else if([self.delegate respondsToSelector:@selector(didReceiveComposingState:user:)])
        [self.delegate didReceiveComposingState:[state intValue] user:user];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)processPresence:(XMLElement*)element
{
    NSString* jid = [element.attributes objectForKey:@"from"];
    //NSLog(@"presence jid: %@\n\n",jid);
    if(jid)
    {
        GPXMPPUser* user = [self userForJID:jid];
        if(!user)
            user = [self roomUserForJID:jid room:nil];
        if(user)
        {
            XMLElement* statusElement = [element findElement:@"status"];
            NSString* status = [statusElement.text stripXMLTags];
            if(status)
                user.status = status;
            NSString* type = [[[element.attributes objectForKey:@"type"] stripXMLTags] lowercaseString];
            GPUserPresence presence = GPUserPresenceAvailable;
            if([type isEqualToString:@"unavailable"])
                presence = GPUserPresenceUnAvailable;
            else if([type isEqualToString:@"available"])
                presence = GPUserPresenceUnAvailable;
            else if([type isEqualToString:@"busy"])
                presence = GPUserPresenceBusy;
            else if(![type isEqualToString:@"error"] && [type rangeOfString:@"subscribe"].location == NSNotFound)
                presence = GPUserPresenceAway;
            
            XMLElement* showElement = [element findElement:@"show"];
            //NSString* statusString = [[showElement findElement:@"status"].text stripXMLTags];
            //NSLog(@"statusString: %@",statusString);
            NSString* showString = showElement.text;
            NSRange range = [showString rangeOfString:@"<"];
            if(range.location != NSNotFound)
                showString = [showString substringToIndex:range.location];
            showString = [[showString stripXMLTags] lowercaseString];
            if([showString isEqualToString:@"chat"])
                presence = GPUserPresenceAvailable;
            else if([showString isEqualToString:@"away"])
                presence = GPUserPresenceAway;
            else if([showString isEqualToString:@"xa"])
                presence = GPUserPresenceAway;
            else if([showString isEqualToString:@"dnd"])
                presence = GPUserPresenceBusy;
            user.presence = presence;
            [self performSelectorOnMainThread:@selector(presenceDelegate:) withObject:user waitUntilDone:NO];
        }
        GPXMPPUser* room = [self roomForJID:jid];
        if(room)
        {
            XMLElement* checkElement = [[NSString stringWithFormat:@"<check>%@</check>",[element convertToString]] XMLObjectFromString];
            NSArray* items = [checkElement findElements:@"item"];
            for(XMLElement* itemElement in items)
            {
                NSString* itemJID = [itemElement.attributes objectForKey:@"jid"];
                GPXMPPUser* itemUser = [self userForJID:itemJID];
                if(!itemUser)
                    itemUser = [self roomUserForJID:itemJID room:nil];
                if(itemUser)
                {
                    if(![room.groupUsers containsObject:itemUser])
                        [room.groupUsers addObject:itemUser];
                }
                else
                {
                    [room.groupUsers addObject:[GPXMPPUser createUser:itemJID name:nil]];
                    [self fetchVCard:itemJID];
                    [self fetchPresence:itemJID];
                }
            }
            [self performSelectorOnMainThread:@selector(roomPresenceDelegate:) withObject:room waitUntilDone:NO];
        }
        
    }
    //NSLog(@"presence: %@",[element convertToString]);
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)presenceDelegate:(GPXMPPUser*)user
{
    if([self.delegate respondsToSelector:@selector(userDidUpdate:update:)])
        [self.delegate userDidUpdate:user update:GPUserTypePresence];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)roomPresenceDelegate:(GPXMPPUser*)room
{
    if([self.delegate respondsToSelector:@selector(didJoinRoom:)])
        [self.delegate didJoinRoom:room];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)elementDelegate:(XMLElement*)element
{
    if([self.delegate respondsToSelector:@selector(didReceiveElement:)])
        [self.delegate didReceiveElement:element];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(NSString*)cleanJID:(NSString*)jid
{
    NSString* checkJID = jid;
    NSRange range = [checkJID rangeOfString:@"/" options:NSStringEnumerationReverse];
    if(range.location != NSNotFound)
        checkJID = [checkJID substringToIndex:range.location];
    return checkJID;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(GPXMPPUser*)userForJID:(NSString*)jid
{
    NSString* checkJID = [self cleanJID:jid];
    for(GPXMPPUser* user in XMPPUsers)
        if([user.JID isEqualToString:checkJID])
            return user;
    if([checkJID isEqualToString:self.userJID])
        return self.streamUser;
    if([jid isEqualToString:self.userJID])
        return self.streamUser;
    if([checkJID isEqualToString:[self cleanJID:self.userJID]])
        return self.streamUser;
    return nil;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(GPXMPPUser*)roomForJID:(NSString*)jid
{
    NSString* checkJID = [self cleanJID:jid];
    for(GPXMPPUser* user in XMPPRooms)
        if([user.JID isEqualToString:checkJID] || [user.JID isEqualToString:jid])
            return user;
    return nil;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(GPXMPPUser*)roomUserForJID:(NSString*)jid room:(GPXMPPUser*)room
{
    if(!room)
    {
        for(GPXMPPUser* checkRoom in XMPPRooms)
        {
            GPXMPPUser* foundRoom = [self roomUserForJID:jid room:checkRoom];
            if(foundRoom)
                return foundRoom;
        }
    }
    NSString* checkJID = [self cleanJID:jid];
    for(GPXMPPUser* user in room.groupUsers)
    {
        if([user.JID isEqualToString:checkJID] || [user.JID isEqualToString:jid] || [[self cleanJID:user.JID] isEqualToString:checkJID])
            return user;
    }
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
    user.groupUsers = [NSMutableArray array];
    [XMPPRooms addObject:user];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)joinRoom:(NSString*)jid
{
    NSString* content = [NSString stringWithFormat:@"<presence to='%@/gpxmpp'><x xmlns='http://jabber.org/protocol/muc'/></presence>",jid];
    if(boshSID)
        [self sendBoshContent:content];
    else
        [socketConnection writeString:content];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)leaveRoom:(NSString*)jid
{
    NSString* content = [NSString stringWithFormat:@"<presence type='unavailable' to='%@'/>",jid];
    if(boshSID)
        [self sendBoshContent:content];
    else
        [socketConnection writeString:content];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//BOSH stuff
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//it is like a normal connection, but with Bosh.
-(void)boshConnect
{
    if(!boshQueue)
    {
        boshQueue = [[NSOperationQueue alloc] init];
        boshQueue.maxConcurrentOperationCount = 2;
    }
    boshRID = [self generateRid];
    GPHTTPRequest* request = [[GPHTTPRequest alloc] initWithString:self.boshURL];
    [request setRequestType:GPHTTPRequestRawPOST];
    [request setCacheModel:GPHTTPIgnoreCache];
    [request addRequestHeader:@"text/xml; charset=utf-8" key:@"Content-Type"];
    [request setTimeout:self.timeout];
    NSString* serverRoute = @"";
    if(self.server)
        serverRoute = [NSString stringWithFormat:@"route='xmpp:%@:%d'",self.server,self.port];
    NSString* formatString = @"<body content='text/xml; charset=utf-8' hold='1' rid='%d' to='%@' %@ ver='1.6' wait='60' ack='1' xml:lang='en' xmlns='http://jabber.org/protocol/httpbind' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>";
    NSString* user = [NSString stringWithFormat:@"%@@%@",self.userName,self.host];
    NSRange range = [user rangeOfString:@":"];
    if(range.location != NSNotFound)
        user = [user substringToIndex:range.location];
    //from='%@'
    [request addPostValue:[NSString stringWithFormat:formatString,boshRID,self.host,serverRoute] key:@"key"];
    [request startSync];
    XMLElement* rootElement = [[request responseString] XMLObjectFromString];
    boshSID = [rootElement.attributes objectForKey:@"sid"];
    //NSLog(@"boshSID: %@",boshSID);
    boshRID++;
    self.timeout = 5;
    if([rootElement.attributes objectForKey:@"polling"])
        self.timeout = [[rootElement.attributes objectForKey:@"polling"] intValue];
    if([rootElement.attributes objectForKey:@"requests"])
         boshQueue.maxConcurrentOperationCount = [[rootElement.attributes objectForKey:@"requests"] intValue];
    XMLElement* features = [rootElement findElement:@"stream:features"];
    [request release];
    NSArray* mechs = [features findElements:@"mechanism"];
    while (!mechs)
    {
        XMLElement* response = [[self syncBoshRequest:@" "] XMLObjectFromString];
        mechs = [response findElements:@"mechanism"];
    }
    
    if([self handleAuthenication:mechs])
    {
        self.isConnected = YES;
        [self resourceBind];
        [self performSelectorOnMainThread:@selector(didConnect) withObject:nil waitUntilDone:NO];
        [self fetchRoster];
        [self fetchVCard:self.userJID];
        [self fetchPresence:nil];
        [self performSelectorOnMainThread:@selector(sendBoshContent:) withObject:@" " waitUntilDone:NO];
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)boshLoop
{
    while(isConnected)
    {
        XMLElement* element = [[self syncBoshRequest:@" "] XMLObjectFromString];
        if(element)
            [self processResponses:element];
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)sendBoshContent:(NSString*)content
{
    GPHTTPRequest* request = [GPHTTPRequest requestWithString:self.boshURL];
    [request setRequestType:GPHTTPRequestRawPOST];
    [request setCacheModel:GPHTTPIgnoreCache];
    [request setDelegate:(id<GPHTTPRequestDelegate>)self];
    [request addRequestHeader:@"text/xml; charset=utf-8" key:@"Content-Type"];
    [request setTimeout:self.timeout];
    NSString* value = [NSString stringWithFormat:@"<body rid='%d' sid='%@' xmlns='http://jabber.org/protocol/httpbind'>%@</body>",boshRID,boshSID,content];
    [request addPostValue:value key:@"key"];
    [boshQueue addOperation:request];
    boshRID++;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)requestFinished:(GPHTTPRequest*)request
{
    //NSLog(@"request finished: %@ postValue: %@",[request responseString],[request postValues]);
    XMLElement* element = [[request responseString] XMLObjectFromString];
    [self processResponses:element];
    [self resendLoop];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)requestFailed:(GPHTTPRequest*)request
{
    if(boshQueue.operationCount == 0)
        [self resendLoop];
    else
        [self performSelector:@selector(sendBoshContent:) withObject:@" " afterDelay:2];
    //NSLog(@"request failed: %@",[request.error userInfo]);
    //NSLog(@"op count: %d",boshQueue.operationCount);
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)resendLoop
{
    if(boshQueue.operationCount < 2)
        [self sendBoshContent:@" "];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(NSString*)syncBoshRequest:(NSString*)content
{
    GPHTTPRequest* request = [GPHTTPRequest requestWithString:self.boshURL];
    [request setRequestType:GPHTTPRequestRawPOST];
    [request setCacheModel:GPHTTPIgnoreCache];
    [request addRequestHeader:@"text/xml; charset=utf-8" key:@"Content-Type"];
    [request addRequestHeader:self.host key:@"Host"];
    [request setTimeout:self.timeout];
    NSString* value = [NSString stringWithFormat:@"<body rid='%d' sid='%@' xmlns='http://jabber.org/protocol/httpbind' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'>%@</body>",boshRID,boshSID,content];
    if(!content)
        value = [NSString stringWithFormat:@"<body rid='%d' sid='%@' xmlns='http://jabber.org/protocol/httpbind' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh' xmpp:restart='true'/>",boshRID,boshSID];
    [request addPostValue:value key:@"key"];
    [request startSync];
    boshRID++;
    return [request responseString];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
- (long long)generateRid
{
    return (arc4random() % 1000000000LL + 1000000001LL);
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)setBoshURL:(NSString *)url
{
    boshURL = url;
    if(self.port == 5222)
        self.port = 5280;
}
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
-(NSString*)decodeString:(NSString*)string
{
    NSString * decodedURL = (NSString *)CFURLCreateStringByReplacingPercentEscapesUsingEncoding(
                                                                                                NULL,
                                                                                                (CFStringRef)string,
                                                                                                CFSTR(""),
                                                                                                kCFStringEncodingUTF8 );
    return [decodedURL autorelease];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
-(void)dealloc
{
    [XMPPUsers release];
    [XMPPRooms release];
    [socketConnection release];
    [boshQueue release];
    [super dealloc];
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
@end


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//helper object
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
@implementation GPXMPPUser

@synthesize name,JID,image,presence,status;
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

