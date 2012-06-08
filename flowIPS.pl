#!/usr/bin/perl
hgfhgf
#===============================================
# But : link netflows datas and IPS datas
#==============================================

# Parameters :
# ./getResponsibleFlow fromDate toDate
# date format : YYYY:MM:DD:hh:mm:ss
#

use strict;
use warnings;
use DBI;

#
# Configuration parameters
#
## Database connexion parameter
require './bdd_parameters.pl';
our %params_bdd;
## Files and directories
my $current_dir = `pwd`; chomp($current_dir);
my $bad_ips_file = "$current_dir/results/bad_ips";
my $flow_record_dir = "$current_dir/nfdumprecord";
my $result_dir = "$current_dir/result"

## Return script values
my $error_file_not_regular  = 10;
my $error_file_not_writable = 11;
my $error_dir_not_writable  = 12;

# file verifications
if (-e $bad_ips_file) {
    if (!(-f $bad_ips_file)) {
        print "The file isn't a regular file (should not be a symbolic link, a socket, ...).\n";
        exit($error_file_not_regular);
    } elsif (!(-w $bad_ips_file)) {
        print "The file is not writable.\n";
        exit($error_file_not_writable);
    }
} else {
    if (!(-x $current_dir)) {
        print "The directory is not writable.\n";
        exit($error_dir_not_writable);
    }
}

# Connection to the database
my $dbh = DBI->connect("dbi:mysql:dbname=$params_bdd{'name'};host=$params_bdd{'server'};", $params_bdd{'user'}, $params_bdd{'password'})
	or die $DBI::errstr; 
	
# Processing
my @bad_ips = select_bad_ips($dbh);
write_bad_ips($bad_ips_file, @bad_ips);

# disconnecting from the database
$dbh->disconnect();

# Calculate time of beginning (timeDebCom) for nfdump command (-R)
my $fromDate = $ARGV[0];
chomp($fromDate);
my ($yearDeb, $monDeb, $dayDeb, $hourDeb, $minDeb, $secDeb) = split /[\/ .:]/, $fromDate;
$yearDeb -= 1900;
$monDeb -= 1;
$timeDebSeconde = mktime($secDeb,$minDeb,$hourDeb,$dayDeb,$monDeb,$yearDeb);
$minDeb = $minDeb - ($minDeb % 5);
my $timeDebCom = strftime("%Y%m%d%H%M",$secDeb,$minDeb,$hourDeb,$mdayDeb,$monDeb,$yearDeb);


# Calculate time of end (timeEndCom) for nfdump command (-R)
my $toDate = $ARGV[1];
chomp($toDate);
my ($yearEnd, $monEnd, $dayEnd, $hourEnd, $minEnd, $secEnd) = split /[\/ . :]/, $toDate;
$yearEnd -= 1900;
$monEnd -= 1;
my $timeEndSeconde = mktime($secEnd,$minEnd,$hourEnd,$dayEnd,$monEnd,$yearEnd);
$minEnd = $minEnd + ($minEnd % 5);
my $timeEndCom = strftime("%Y%m%d%H%M",$secEnd,$minEnd,$hourEnd,$mdayEnd,$monEnd,$yearEnd);



# Main loop : For each IP in Blacklist
open (BLACKLIST,$blPath) or die ("Can't open ".$blPath);
while($attIp = <BLACKLIST>) { 

	# Get the flow to analyze 
	@flowsToAnalyze = `nfdump -q -R nfcapd.$timeDebCom:nfcapd.$timeEndCom -M $flow_record_dir -t $timeDebWindow-$timeEndWindow 
	"dst ip $attIp" -o 'fmt:%td|%sp|%dp|%pkt|%byt'`;

	#TODO : Print result in a file
}
close BLACKLIST or die $!;

#
# Put every destination ip into a file
# For the moment we override the file content and put all the ips inside, one per line.
#
# @param $file The absolute path to the file in which the ips wiil be written.
# @param @ips  An array of ips.
# @return 0 if everything went ok, strictly positive number otherwise.
#
sub write_bad_ips {
    my ($file, @ips) = @_;

	if (!open(BAD_IPS_FILE, ">$file")) {
		print "An error occured while opening the file hosting ips : $!.\n";
		exit(1);
	}
    
    while (@ips) {
        my $ip = shift @ips;  
        printf (BAD_IPS_FILE "$ip\n");
    }
    close(BAD_IPS_FILE);
    print "Bad ips written\n";
    
    return 1;
}

#
# Select all destinations ips fromm the IPS datas
#
# @ param  $dbh Database handler object
# @ return @ips An array of ips
#
sub select_bad_ips {
	my $dbh = shift;

	my @bad_ips;
	my $prep = $dbh->prepare('SELECT dip FROM 2012_events LIMIT 0,30') or die $dbh->errstr;
	$prep->execute() or die "The query selecting bad_ips failed\n";
	while (my($ip) = $prep->fetchrow_array) {
		push(@bad_ips, $ip);
	}
	$prep->finish();
	
	print "Bad ips selected\n";

	return @bad_ips;
}




