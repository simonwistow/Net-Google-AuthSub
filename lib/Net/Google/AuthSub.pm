package Net::Google::AuthSub;

use strict;
use vars qw($VERSION $APP_NAME);
use LWP::UserAgent;
use HTTP::Request::Common;
use Net::Google::AuthSub::Response;

$VERSION  = '0.1';
$APP_NAME = __PACKAGE__."-".$VERSION;

use constant CLIENT_LOGIN => 0;
use constant AUTH_SUB     => 1;

=head1 NAME

Net::Google::AuthSub - interact with sites that implement Google style AuthSub

=head1 SYNOPSIS


    my $auth = Net::Google::AuthSub->new;
    my $response = $auth->login($user, $pass);

    if ($response->is_success) {
        print "Hurrah! Logged in\n";
    } else {
        die "Login failed: ".$response->error."\n";
    }

    my %params = $auth->auth_params;
    $params{Content_Type}             = 'application/atom+xml; charset=UTF-8';
    $params{Content}                  = $xml;
    $params{'X-HTTP-Method-Override'} = 'DELETE';        

    my $request = POST $url, %params;
    my $r = $user_agent->request( $request );


=head1 ABOUT AUTHSUB

AuthSub is Google's method of authentication for their web 
services. It is also used by other web sites.

You can read more about it here.

    http://code.google.com/apis/accounts/Authentication.html

A Google Group for AuthSub is here.

    http://groups.google.com/group/Google-Accounts-API

=head1 DEALING WITH CAPTCHAS

If a login response fails then it may set the error code to
'CaptchRequired' and the response object will allow you to 
retrieve the C<captchatoken> and C<captchaurl> fields.

The C<captchaurl> will be the url to a captcha image or you 
can show the user the web page

    https://www.google.com/accounts/DisplayUnlockCaptcha

Then retry the login attempt passing in the parameters 
C<logintoken> (which is the value of C<captchatoken>) and 
C<logincaptcha> which is the user's answer to the CAPTCHA.


    my $auth = Net::Google::AuthSub->new;
    my $res  = $auth->login($user, $pass);

    if (!$res->is_success && $res->error eq 'CaptchaRequired') {
        my $answer = display_captcha($res->captchaurl);
        $auth->login($user, $pass, logintoken => $res->captchatoken, logincaptcha => $answer);
    }


You can read more here

    http://code.google.com/apis/accounts/AuthForInstalledApps.html#Using

=head1 METHODS

=cut

=head2 new [param[s]]

Return a new authorisation object. The options are

=over 4

=item url

The base url of the web service to authenticate against.

Defaults to C<http://google.com>

=item service

Name of the Google service for which authorization is requested such as 'cl' for Calendar.

Defaults to 'xapi' for calendar.

=item source

Short string identifying your application, for logging purposes.

Defaults to 'Net::Google::AuthSub-<VERSION>'

=item accountType

Type of account to be authenticated.

Defaults to 'HOSTED_OR_GOOGLE'.

=back

See http://code.google.com/apis/accounts/AuthForInstalledApps.html#ClientLogin for more details.

=cut


sub new {
    my $class  = shift;
    my %params = @_;

    $params{_ua}           = LWP::UserAgent->new;    
    $params{url}         ||= 'https://google.com';
    $params{service}     ||= 'xapi';
    $params{source}      ||= $APP_NAME;
    $params{accountType} ||= 'HOSTED_OR_GOOGLE';


    return bless \%params, $class;
}

=head2 login <username> <password> [opt[s]]

Login to google using your username and password.

Can optionally take a hash of options which will override the 
default login params. 

Returns a C<Net::Google::AuthSub::Response> object.

=cut

sub login {
    my ($self, $user, $pass, %opts) = @_;

    # setup auth request
    my %params = ( Email       => $user, 
                   Passwd      => $pass, 
                   service     => $self->{service}, 
                   source      => $self->{source},
                   accountType => $self->{accountType} );
    # allow overrides
    $params{$_} = $opts{$_} for (keys %opts);

    my $tmp = $self->{_ua}->request(POST $self->{url}.'/accounts/ClientLogin', [ %params ]);
    my $r = Net::Google::AuthSub::Response->new($tmp, $self->{url});
    return $r unless $r->is_success;


    # store auth token
    $self->{_auth}      = $r->auth;
    $self->{_auth_type} = CLIENT_LOGIN;
    $self->{user}       = $user;
    $self->{pass}       = $pass; 
    return $r;

}

=head2 authorised 

Whether or not we're authorised.

=cut

sub authorised {
    my $self = shift;
    return defined $self->{_auth};

}

=head2 auth <username> <token>

Use the AuthSub method for access.

See http://code.google.com/apis/accounts/AuthForWebApps.html 
for details.

=cut

sub auth {
    my ($self, $username, $token) = @_;
    $self->{_auth}      = $token;
    $self->{_auth_type} = AUTH_SUB;
    $self->{user}       = $username;
    return 1;
}

=head2 auth_params

Return any parameters needed in an HTTP request to authorise your app.

=cut

sub auth_params {
    my $self  = shift;
    return () unless $self->authorised;
    return ( Authorization => $self->_auth_string );
}

my %AUTH_TYPES = ( CLIENT_LOGIN() => "GoogleLogin auth", AUTH_SUB() => "AuthSub token" );

sub _auth_string {
    my $self   = shift;
    return "" unless $self->authorised;
    return $AUTH_TYPES{$self->{_auth_type}}."=".$self->{_auth};
}


=head1 AUTHOR

Simon Wistow <simon@thegestalt.org>

=head1 COPYRIGHT

COpyright, 2007 - Simon Wistow

Released under the same terms as Perl itself

=cut


1;
