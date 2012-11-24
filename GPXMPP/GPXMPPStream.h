/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//  GPXMPPStream.h
//  GPXMPP
//
//  Created by Dalton Cherry on 9/8/12.
//  Copyright (c) 2012 Basement Krew. All rights reserved.
//
/////////////////////////////////////////////////////////////////////////////////////////////////////////////

#import <Foundation/Foundation.h>
#import "../GPSocket/GPSocket.h"
#import "../XMLKit/XMLKit.h"

@interface GPXMPPUser : NSObject

typedef enum {
    GPUserPresenceAvailable,
    GPUserPresenceUnAvailable,
    GPUserPresenceAway,
    GPUserPresenceBusy
} GPUserPresence;

@property(nonatomic,copy)NSString* name;
@property(nonatomic,copy)NSString* JID;
@property(nonatomic,retain)NSData* image; //this is your image, I am doing this to work on the mac as well
@property(nonatomic,assign)GPUserPresence presence;
@property(nonatomic,copy)NSString* status;
@property(nonatomic,assign)BOOL isGroup;
@property(nonatomic,retain)NSMutableArray* groupUsers;

+(GPXMPPUser*)createUser:(NSString*)JID name:(NSString*)name;

@end
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef enum {
    GPUserTypeVcard,
    GPUserTypePresence
} GPUserUpdateType;
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
@protocol GPXMPPStreamDelegate <NSObject>

//got the roster info
-(void)didReceiveRoster:(NSArray*)users;

//a user updated in someway. (presence,vCard,etc)
-(void)userDidUpdate:(GPXMPPUser*)user update:(GPUserUpdateType)updateState;

//you got a message from a user.
-(void)didReceiveMessage:(NSString*)message user:(GPXMPPUser*)user;

//default fall through for any kind of message that does not match other delegates
-(void)didReceiveElement:(XMLElement*)element;

//the stream is setup and ready to be written/listened from.
-(void)streamDidConnect;

//the stream failed to authenication.
-(void)streamDidFailLogin;

//got the room info
-(void)didReceiveRooms:(NSArray*)rooms;

//got the room users and room was joined
-(void)didJoinRoom:(GPXMPPUser*)room;

@end

@interface GPXMPPStream : NSObject
{
    GPSocket* socketConnection;
}

//set your port. Defalut is 5222.
@property(nonatomic,assign)NSInteger port;

//set your host. This just be something like gmail.com
@property(nonatomic,copy)NSString* host;

//set your server. This should be something like: talk.google.com
@property(nonatomic,copy)NSString* server;

//set your user name. This should be something like: username@gmail.com
@property(nonatomic,copy)NSString* userName;

//set your password. This should be the password for your userName.
@property(nonatomic,copy)NSString* password;

//this gets set by the stream.
@property(nonatomic,copy)NSString* userJID; //the jid of the authenicated user

//this gets set by the stream. It is the GPXMPPUser object for the user logged into the stream
@property(nonatomic,retain)GPXMPPUser* streamUser;

//normal delegate implementation
@property(nonatomic,assign)id<GPXMPPStreamDelegate>delegate;

//is an array of XMPPUsers from your roster.
@property(nonatomic,retain)NSMutableArray* XMPPUsers;

//is an array of XMPPUsers from your rooms.
@property(nonatomic,retain)NSMutableArray* XMPPRooms;

//shared stream instance.
+(GPXMPPStream*)sharedStream;

//start the connection.
-(void)connect;

//write an element to the stream
-(void)writeElement:(XMLElement*)element;

//send a message to a user
-(void)sendMessage:(NSString*)message JID:(NSString*)jidString;

//fetch the roster.
-(void)fetchRoster;

//fetch Presence of user
-(void)fetchPresence:(NSString*)jidString;

//fetch the bookmarks
-(void)fetchBookmarks;

//fetch VCard from a jidString
-(void)fetchVCard:(NSString*)jidString;

//get a userObject from the jid
-(GPXMPPUser*)userForJID:(NSString*)jid;

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//group/room chat. XEP-0045
/////////////////////////////////////////////////////////////////////////////////////////////////////////////

//add a room
-(void)addRoom:(NSString*)jid name:(NSString*)nickName;

//join a room
-(void)joinRoom:(NSString*)jid;

//leave room
-(void)leaveRoom:(NSString*)jid;

//get a userObject from the jid
-(GPXMPPUser*)roomForJID:(NSString*)jid;

@end
