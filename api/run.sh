#!/usr/bin/bash

postgrest postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@postgres/$POSTGRES_DB -a anon
