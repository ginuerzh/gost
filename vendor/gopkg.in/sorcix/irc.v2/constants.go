// Copyright 2014 Vic Demuzere
//
// Use of this source code is governed by the MIT license.

package irc

// Various prefixes extracted from RFC 1459.
const (
	Channel     = '#' // Normal channel
	Distributed = '&' // Distributed channel

	Owner        = '~' // Channel owner +q (non-standard)
	Admin        = '&' // Channel admin +a (non-standard)
	Operator     = '@' // Channel operator +o
	HalfOperator = '%' // Channel half operator +h (non-standard)
	Voice        = '+' // User has voice +v
)

// User modes as defined by RFC 1459 section 4.2.3.2.
const (
	UserModeInvisible     = 'i' // User is invisible
	UserModeServerNotices = 's' // User wants to receive server notices
	UserModeWallops       = 'w' // User wants to receive Wallops
	UserModeOperator      = 'o' // Server operator
)

// Channel modes as defined by RFC 1459 section 4.2.3.1
const (
	ModeOperator   = 'o' // Operator privileges
	ModeVoice      = 'v' // Ability to speak on a moderated channel
	ModePrivate    = 'p' // Private channel
	ModeSecret     = 's' // Secret channel
	ModeInviteOnly = 'i' // Users can't join without invite
	ModeTopic      = 't' // Topic can only be set by an operator
	ModeModerated  = 'm' // Only voiced users and operators can talk
	ModeLimit      = 'l' // User limit
	ModeKey        = 'k' // Channel password

	ModeOwner        = 'q' // Owner privileges (non-standard)
	ModeAdmin        = 'a' // Admin privileges (non-standard)
	ModeHalfOperator = 'h' // Half-operator privileges (non-standard)
)

// IRC commands extracted from RFC 2812 section 3 and RFC 2813 section 4.
const (
	PASS     = "PASS"
	NICK     = "NICK"
	USER     = "USER"
	OPER     = "OPER"
	MODE     = "MODE"
	SERVICE  = "SERVICE"
	QUIT     = "QUIT"
	SQUIT    = "SQUIT"
	JOIN     = "JOIN"
	PART     = "PART"
	TOPIC    = "TOPIC"
	NAMES    = "NAMES"
	LIST     = "LIST"
	INVITE   = "INVITE"
	KICK     = "KICK"
	PRIVMSG  = "PRIVMSG"
	NOTICE   = "NOTICE"
	MOTD     = "MOTD"
	LUSERS   = "LUSERS"
	VERSION  = "VERSION"
	STATS    = "STATS"
	LINKS    = "LINKS"
	TIME     = "TIME"
	CONNECT  = "CONNECT"
	TRACE    = "TRACE"
	ADMIN    = "ADMIN"
	INFO     = "INFO"
	SERVLIST = "SERVLIST"
	SQUERY   = "SQUERY"
	WHO      = "WHO"
	WHOIS    = "WHOIS"
	WHOWAS   = "WHOWAS"
	KILL     = "KILL"
	PING     = "PING"
	PONG     = "PONG"
	ERROR    = "ERROR"
	AWAY     = "AWAY"
	REHASH   = "REHASH"
	DIE      = "DIE"
	RESTART  = "RESTART"
	SUMMON   = "SUMMON"
	USERS    = "USERS"
	WALLOPS  = "WALLOPS"
	USERHOST = "USERHOST"
	ISON     = "ISON"
	SERVER   = "SERVER"
	NJOIN    = "NJOIN"
)

// Numeric IRC replies extracted from RFC 2812 section 5.
const (
	RPL_WELCOME           = "001"
	RPL_YOURHOST          = "002"
	RPL_CREATED           = "003"
	RPL_MYINFO            = "004"
	RPL_BOUNCE            = "005"
	RPL_ISUPPORT          = "005"
	RPL_USERHOST          = "302"
	RPL_ISON              = "303"
	RPL_AWAY              = "301"
	RPL_UNAWAY            = "305"
	RPL_NOWAWAY           = "306"
	RPL_WHOISUSER         = "311"
	RPL_WHOISSERVER       = "312"
	RPL_WHOISOPERATOR     = "313"
	RPL_WHOISIDLE         = "317"
	RPL_ENDOFWHOIS        = "318"
	RPL_WHOISCHANNELS     = "319"
	RPL_WHOWASUSER        = "314"
	RPL_ENDOFWHOWAS       = "369"
	RPL_LISTSTART         = "321"
	RPL_LIST              = "322"
	RPL_LISTEND           = "323"
	RPL_UNIQOPIS          = "325"
	RPL_CHANNELMODEIS     = "324"
	RPL_NOTOPIC           = "331"
	RPL_TOPIC             = "332"
	RPL_INVITING          = "341"
	RPL_SUMMONING         = "342"
	RPL_INVITELIST        = "346"
	RPL_ENDOFINVITELIST   = "347"
	RPL_EXCEPTLIST        = "348"
	RPL_ENDOFEXCEPTLIST   = "349"
	RPL_VERSION           = "351"
	RPL_WHOREPLY          = "352"
	RPL_ENDOFWHO          = "315"
	RPL_NAMREPLY          = "353"
	RPL_ENDOFNAMES        = "366"
	RPL_LINKS             = "364"
	RPL_ENDOFLINKS        = "365"
	RPL_BANLIST           = "367"
	RPL_ENDOFBANLIST      = "368"
	RPL_INFO              = "371"
	RPL_ENDOFINFO         = "374"
	RPL_MOTDSTART         = "375"
	RPL_MOTD              = "372"
	RPL_ENDOFMOTD         = "376"
	RPL_YOUREOPER         = "381"
	RPL_REHASHING         = "382"
	RPL_YOURESERVICE      = "383"
	RPL_TIME              = "391"
	RPL_USERSSTART        = "392"
	RPL_USERS             = "393"
	RPL_ENDOFUSERS        = "394"
	RPL_NOUSERS           = "395"
	RPL_TRACELINK         = "200"
	RPL_TRACECONNECTING   = "201"
	RPL_TRACEHANDSHAKE    = "202"
	RPL_TRACEUNKNOWN      = "203"
	RPL_TRACEOPERATOR     = "204"
	RPL_TRACEUSER         = "205"
	RPL_TRACESERVER       = "206"
	RPL_TRACESERVICE      = "207"
	RPL_TRACENEWTYPE      = "208"
	RPL_TRACECLASS        = "209"
	RPL_TRACERECONNECT    = "210"
	RPL_TRACELOG          = "261"
	RPL_TRACEEND          = "262"
	RPL_STATSLINKINFO     = "211"
	RPL_STATSCOMMANDS     = "212"
	RPL_ENDOFSTATS        = "219"
	RPL_STATSUPTIME       = "242"
	RPL_STATSOLINE        = "243"
	RPL_UMODEIS           = "221"
	RPL_SERVLIST          = "234"
	RPL_SERVLISTEND       = "235"
	RPL_LUSERCLIENT       = "251"
	RPL_LUSEROP           = "252"
	RPL_LUSERUNKNOWN      = "253"
	RPL_LUSERCHANNELS     = "254"
	RPL_LUSERME           = "255"
	RPL_ADMINME           = "256"
	RPL_ADMINLOC1         = "257"
	RPL_ADMINLOC2         = "258"
	RPL_ADMINEMAIL        = "259"
	RPL_TRYAGAIN          = "263"
	ERR_NOSUCHNICK        = "401"
	ERR_NOSUCHSERVER      = "402"
	ERR_NOSUCHCHANNEL     = "403"
	ERR_CANNOTSENDTOCHAN  = "404"
	ERR_TOOMANYCHANNELS   = "405"
	ERR_WASNOSUCHNICK     = "406"
	ERR_TOOMANYTARGETS    = "407"
	ERR_NOSUCHSERVICE     = "408"
	ERR_NOORIGIN          = "409"
	ERR_NORECIPIENT       = "411"
	ERR_NOTEXTTOSEND      = "412"
	ERR_NOTOPLEVEL        = "413"
	ERR_WILDTOPLEVEL      = "414"
	ERR_BADMASK           = "415"
	ERR_UNKNOWNCOMMAND    = "421"
	ERR_NOMOTD            = "422"
	ERR_NOADMININFO       = "423"
	ERR_FILEERROR         = "424"
	ERR_NONICKNAMEGIVEN   = "431"
	ERR_ERRONEUSNICKNAME  = "432"
	ERR_NICKNAMEINUSE     = "433"
	ERR_NICKCOLLISION     = "436"
	ERR_UNAVAILRESOURCE   = "437"
	ERR_USERNOTINCHANNEL  = "441"
	ERR_NOTONCHANNEL      = "442"
	ERR_USERONCHANNEL     = "443"
	ERR_NOLOGIN           = "444"
	ERR_SUMMONDISABLED    = "445"
	ERR_USERSDISABLED     = "446"
	ERR_NOTREGISTERED     = "451"
	ERR_NEEDMOREPARAMS    = "461"
	ERR_ALREADYREGISTRED  = "462"
	ERR_NOPERMFORHOST     = "463"
	ERR_PASSWDMISMATCH    = "464"
	ERR_YOUREBANNEDCREEP  = "465"
	ERR_YOUWILLBEBANNED   = "466"
	ERR_KEYSET            = "467"
	ERR_CHANNELISFULL     = "471"
	ERR_UNKNOWNMODE       = "472"
	ERR_INVITEONLYCHAN    = "473"
	ERR_BANNEDFROMCHAN    = "474"
	ERR_BADCHANNELKEY     = "475"
	ERR_BADCHANMASK       = "476"
	ERR_NOCHANMODES       = "477"
	ERR_BANLISTFULL       = "478"
	ERR_NOPRIVILEGES      = "481"
	ERR_CHANOPRIVSNEEDED  = "482"
	ERR_CANTKILLSERVER    = "483"
	ERR_RESTRICTED        = "484"
	ERR_UNIQOPPRIVSNEEDED = "485"
	ERR_NOOPERHOST        = "491"
	ERR_UMODEUNKNOWNFLAG  = "501"
	ERR_USERSDONTMATCH    = "502"
)

// IRC commands extracted from the IRCv3 spec at http://www.ircv3.org/.
const (
	CAP       = "CAP"
	CAP_LS    = "LS"    // Subcommand (param)
	CAP_LIST  = "LIST"  // Subcommand (param)
	CAP_REQ   = "REQ"   // Subcommand (param)
	CAP_ACK   = "ACK"   // Subcommand (param)
	CAP_NAK   = "NAK"   // Subcommand (param)
	CAP_CLEAR = "CLEAR" // Subcommand (param)
	CAP_END   = "END"   // Subcommand (param)

	AUTHENTICATE = "AUTHENTICATE"
)

// Numeric IRC replies extracted from the IRCv3 spec.
const (
	RPL_LOGGEDIN    = "900"
	RPL_LOGGEDOUT   = "901"
	RPL_NICKLOCKED  = "902"
	RPL_SASLSUCCESS = "903"
	ERR_SASLFAIL    = "904"
	ERR_SASLTOOLONG = "905"
	ERR_SASLABORTED = "906"
	ERR_SASLALREADY = "907"
	RPL_SASLMECHS   = "908"
)

// RFC 2812 section 5.3
const (
	RPL_STATSCLINE    = "213"
	RPL_STATSNLINE    = "214"
	RPL_STATSILINE    = "215"
	RPL_STATSKLINE    = "216"
	RPL_STATSQLINE    = "217"
	RPL_STATSYLINE    = "218"
	RPL_SERVICEINFO   = "231"
	RPL_ENDOFSERVICES = "232"
	RPL_SERVICE       = "233"
	RPL_STATSVLINE    = "240"
	RPL_STATSLLINE    = "241"
	RPL_STATSHLINE    = "244"
	RPL_STATSSLINE    = "245"
	RPL_STATSPING     = "246"
	RPL_STATSBLINE    = "247"
	RPL_STATSDLINE    = "250"
	RPL_NONE          = "300"
	RPL_WHOISCHANOP   = "316"
	RPL_KILLDONE      = "361"
	RPL_CLOSING       = "362"
	RPL_CLOSEEND      = "363"
	RPL_INFOSTART     = "373"
	RPL_MYPORTIS      = "384"
	ERR_NOSERVICEHOST = "492"
)

// Other constants
const (
	ERR_TOOMANYMATCHES = "416" // Used on IRCNet
	RPL_TOPICWHOTIME   = "333" // From ircu, in use on Freenode
	RPL_LOCALUSERS     = "265" // From aircd, Hybrid, Hybrid, Bahamut, in use on Freenode
	RPL_GLOBALUSERS    = "266" // From aircd, Hybrid, Hybrid, Bahamut, in use on Freenode
)
