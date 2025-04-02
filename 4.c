pq_getmessage(StringInfo s, int maxlen)
{
	int32		len;

	resetStringInfo(s);

	/* Read message length word */
	if (pq_getbytes((char *) &len, 4) == EOF)
	{
		ereport(COMMERROR,
				(errcode(ERRCODE_PROTOCOL_VIOLATION),
				 errmsg("unexpected EOF within message length word")));
		return EOF;
	}

	len = ntohl(len);

	if (len < 4 ||
		(maxlen > 0 && len > maxlen))
	{
		ereport(COMMERROR,
				(errcode(ERRCODE_PROTOCOL_VIOLATION),
				 errmsg("invalid message length")));
		return EOF;
	}

	len -= 4;					/* discount length itself */

	if (len > 0)
	{
		/*
		 * Allocate space for message.  If we run out of room (ridiculously
		 * large message), we will elog(ERROR), but we want to discard the
		 * message body so as not to lose communication sync.
		 */
		PG_TRY();
		{
			enlargeStringInfo(s, len);
		}
		PG_CATCH();
		{
			if (pq_discardbytes(len) == EOF)
				ereport(COMMERROR,
						(errcode(ERRCODE_PROTOCOL_VIOLATION),
						 errmsg("incomplete message from client")));
			PG_RE_THROW();
		}
		PG_END_TRY();

		/* And grab the message */
		if (pq_getbytes(s->data, len) == EOF)
		{
			ereport(COMMERROR,
					(errcode(ERRCODE_PROTOCOL_VIOLATION),
					 errmsg("incomplete message from client")));
			return EOF;
		}
		s->len = len;
		/* Place a trailing null per StringInfo convention */
		s->data[len] = '\0';
	}

	return 0;
}
