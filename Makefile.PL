use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	NAME		=> 'Net::TinySRTP',
	VERSION_FROM	=> 'lib/Net/TinySRTP.pm',	# finds $VERSION, requires EU::MM from perl >= 5.5
	PREREQ_PM	=> {},				# e.g., Module::Name => 1.1
	ABSTRACT_FROM	=> 'lib/Net/TinySRTP.pm',	# retrieve abstract from module
	AUTHOR		=> 'nabe@abk',
	LICENSE		=> 'perl',			#https://metacpan.org/pod/Module::Build::API
	LIBS		=> ['-lssl -lcrypto'],		# e.g., '-lm'
	DEFINE		=> '',				# e.g., '-DHAVE_SOMETHING'
	INC		=> '-I.',			# e.g., '-I. -I/usr/include/other'
	# OBJECT	=> '$(O_FILES)',		# link all the C files too

	clean		=> { FILES => [ qw(example/dtls_client example/dtls_server) ] }
);
