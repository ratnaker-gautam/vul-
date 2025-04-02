pg_SSPI_recvauth(Port *port)
{
	int			mtype;
	StringInfoData buf;
	SECURITY_STATUS r;
	CredHandle	sspicred;
	CtxtHandle *sspictx = NULL,
				newctx;
	TimeStamp	expiry;
	ULONG		contextattr;
	SecBufferDesc inbuf;
	SecBufferDesc outbuf;
	SecBuffer	OutBuffers[1];
	SecBuffer	InBuffers[1];
	HANDLE		token;
	TOKEN_USER *tokenuser;
	DWORD		retlen;
	char		accountname[MAXPGPATH];
	char		domainname[MAXPGPATH];
	DWORD		accountnamesize = sizeof(accountname);
	DWORD		domainnamesize = sizeof(domainname);
	SID_NAME_USE accountnameuse;
	HMODULE		secur32;
	QUERY_SECURITY_CONTEXT_TOKEN_FN _QuerySecurityContextToken;

	/*
	 * SSPI auth is not supported for protocol versions before 3, because it
	 * relies on the overall message length word to determine the SSPI payload
	 * size in AuthenticationGSSContinue and PasswordMessage messages. (This
	 * is, in fact, a design error in our SSPI support, because protocol
	 * messages are supposed to be parsable without relying on the length
	 * word; but it's not worth changing it now.)
	 */
	if (PG_PROTOCOL_MAJOR(FrontendProtocol) < 3)
		ereport(FATAL,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SSPI is not supported in protocol version 2")));

	/*
	 * Acquire a handle to the server credentials.
	 */
	r = AcquireCredentialsHandle(NULL,
								 "negotiate",
								 SECPKG_CRED_INBOUND,
								 NULL,
								 NULL,
								 NULL,
								 NULL,
								 &sspicred,
								 &expiry);
	if (r != SEC_E_OK)
		pg_SSPI_error(ERROR, _("could not acquire SSPI credentials"), r);

	/*
	 * Loop through SSPI message exchange. This exchange can consist of
	 * multiple messags sent in both directions. First message is always from
	 * the client. All messages from client to server are password packets
	 * (type 'p').
	 */
	do
	{
		mtype = pq_getbyte();
		if (mtype != 'p')
		{
			/* Only log error if client didn't disconnect. */
			if (mtype != EOF)
				ereport(COMMERROR,
						(errcode(ERRCODE_PROTOCOL_VIOLATION),
						 errmsg("expected SSPI response, got message type %d",
								mtype)));
			return STATUS_ERROR;
		}

		/* Get the actual SSPI token */
		initStringInfo(&buf);
		if (pq_getmessage(&buf, PG_MAX_AUTH_TOKEN_LENGTH))
		{
			/* EOF - pq_getmessage already logged error */
			pfree(buf.data);
			return STATUS_ERROR;
		}

		/* Map to SSPI style buffer */
		inbuf.ulVersion = SECBUFFER_VERSION;
		inbuf.cBuffers = 1;
		inbuf.pBuffers = InBuffers;
		InBuffers[0].pvBuffer = buf.data;
		InBuffers[0].cbBuffer = buf.len;
		InBuffers[0].BufferType = SECBUFFER_TOKEN;

		/* Prepare output buffer */
		OutBuffers[0].pvBuffer = NULL;
		OutBuffers[0].BufferType = SECBUFFER_TOKEN;
		OutBuffers[0].cbBuffer = 0;
		outbuf.cBuffers = 1;
		outbuf.pBuffers = OutBuffers;
		outbuf.ulVersion = SECBUFFER_VERSION;


		elog(DEBUG4, "Processing received SSPI token of length %u",
			 (unsigned int) buf.len);

		r = AcceptSecurityContext(&sspicred,
								  sspictx,
								  &inbuf,
								  ASC_REQ_ALLOCATE_MEMORY,
								  SECURITY_NETWORK_DREP,
								  &newctx,
								  &outbuf,
								  &contextattr,
								  NULL);

		/* input buffer no longer used */
		pfree(buf.data);

		if (outbuf.cBuffers > 0 && outbuf.pBuffers[0].cbBuffer > 0)
		{
			/*
			 * Negotiation generated data to be sent to the client.
			 */
			elog(DEBUG4, "sending SSPI response token of length %u",
				 (unsigned int) outbuf.pBuffers[0].cbBuffer);

			port->gss->outbuf.length = outbuf.pBuffers[0].cbBuffer;
			port->gss->outbuf.value = outbuf.pBuffers[0].pvBuffer;

			sendAuthRequest(port, AUTH_REQ_GSS_CONT);

			FreeContextBuffer(outbuf.pBuffers[0].pvBuffer);
		}

		if (r != SEC_E_OK && r != SEC_I_CONTINUE_NEEDED)
		{
			if (sspictx != NULL)
			{
				DeleteSecurityContext(sspictx);
				free(sspictx);
			}
			FreeCredentialsHandle(&sspicred);
			pg_SSPI_error(ERROR,
						  _("could not accept SSPI security context"), r);
		}

		/*
		 * Overwrite the current context with the one we just received. If
		 * sspictx is NULL it was the first loop and we need to allocate a
		 * buffer for it. On subsequent runs, we can just overwrite the buffer
		 * contents since the size does not change.
		 */
		if (sspictx == NULL)
		{
			sspictx = malloc(sizeof(CtxtHandle));
			if (sspictx == NULL)
				ereport(ERROR,
						(errmsg("out of memory")));
		}

		memcpy(sspictx, &newctx, sizeof(CtxtHandle));

		if (r == SEC_I_CONTINUE_NEEDED)
			elog(DEBUG4, "SSPI continue needed");

	} while (r == SEC_I_CONTINUE_NEEDED);


	/*
	 * Release service principal credentials
	 */
	FreeCredentialsHandle(&sspicred);


	/*
	 * SEC_E_OK indicates that authentication is now complete.
	 *
	 * Get the name of the user that authenticated, and compare it to the pg
	 * username that was specified for the connection.
	 *
	 * MingW is missing the export for QuerySecurityContextToken in the
	 * secur32 library, so we have to load it dynamically.
	 */

	secur32 = LoadLibrary("SECUR32.DLL");
	if (secur32 == NULL)
		ereport(ERROR,
				(errmsg_internal("could not load secur32.dll: error code %lu",
								 GetLastError())));

	_QuerySecurityContextToken = (QUERY_SECURITY_CONTEXT_TOKEN_FN)
		GetProcAddress(secur32, "QuerySecurityContextToken");
	if (_QuerySecurityContextToken == NULL)
	{
		FreeLibrary(secur32);
		ereport(ERROR,
				(errmsg_internal("could not locate QuerySecurityContextToken in secur32.dll: error code %lu",
								 GetLastError())));
	}

	r = (_QuerySecurityContextToken) (sspictx, &token);
	if (r != SEC_E_OK)
	{
		FreeLibrary(secur32);
		pg_SSPI_error(ERROR,
					  _("could not get token from SSPI security context"), r);
	}

	FreeLibrary(secur32);

	/*
	 * No longer need the security context, everything from here on uses the
	 * token instead.
	 */
	DeleteSecurityContext(sspictx);
	free(sspictx);

	if (!GetTokenInformation(token, TokenUser, NULL, 0, &retlen) && GetLastError() != 122)
		ereport(ERROR,
			(errmsg_internal("could not get token user size: error code %lu",
							 GetLastError())));

	tokenuser = malloc(retlen);
	if (tokenuser == NULL)
		ereport(ERROR,
				(errmsg("out of memory")));

	if (!GetTokenInformation(token, TokenUser, tokenuser, retlen, &retlen))
		ereport(ERROR,
				(errmsg_internal("could not get user token: error code %lu",
								 GetLastError())));

	if (!LookupAccountSid(NULL, tokenuser->User.Sid, accountname, &accountnamesize,
						  domainname, &domainnamesize, &accountnameuse))
		ereport(ERROR,
			(errmsg_internal("could not look up account SID: error code %lu",
							 GetLastError())));

	free(tokenuser);

	/*
	 * Compare realm/domain if requested. In SSPI, always compare case
	 * insensitive.
	 */
	if (port->hba->krb_realm && strlen(port->hba->krb_realm))
	{
		if (pg_strcasecmp(port->hba->krb_realm, domainname) != 0)
		{
			elog(DEBUG2,
				 "SSPI domain (%s) and configured domain (%s) don't match",
				 domainname, port->hba->krb_realm);

			return STATUS_ERROR;
		}
	}

	/*
	 * We have the username (without domain/realm) in accountname, compare to
	 * the supplied value. In SSPI, always compare case insensitive.
	 *
	 * If set to include realm, append it in <username>@<realm> format.
	 */
	if (port->hba->include_realm)
	{
		char	   *namebuf;
		int			retval;

		namebuf = psprintf("%s@%s", accountname, domainname);
		retval = check_usermap(port->hba->usermap, port->user_name, namebuf, true);
		pfree(namebuf);
		return retval;
	}
	else
		return check_usermap(port->hba->usermap, port->user_name, accountname, true);
}
