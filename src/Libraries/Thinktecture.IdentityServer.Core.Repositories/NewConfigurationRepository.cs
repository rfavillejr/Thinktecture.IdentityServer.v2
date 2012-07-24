﻿using System;
using Thinktecture.IdentityServer.Repositories.Configuration;
using Thinktecture.IdentityServer.Repositories.Sql;
using System.Linq;
using Thinktecture.IdentityServer.Repositories.Sql.Configuration;
using Models = Thinktecture.IdentityServer.Models;
using Entities = Thinktecture.IdentityServer.Repositories.Sql;

namespace Thinktecture.IdentityServer.Core.Repositories
{
    public class NewConfigurationRepository : IConfigurationRepository
    {
        public bool SupportsWriteAccess
        {
            get { return true; }
        }

        public Models.Configuration.GlobalConfiguration Global
        {
            get
            {
                using (var entities = NewIdentityServerConfigurationContext.Get())
                {
                    var config = entities.GlobalConfiguration.First<Entities.Configuration.GlobalConfiguration>();

                    // map to domain model
                    return config.ToDomainModel();
                }
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public Models.Configuration.DiagnosticsConfiguration Diagnostics
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public Models.Configuration.KeyMaterialConfiguration Keys
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public Models.Configuration.WSFederationConfiguration WSFederation
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public Models.Configuration.FederationMetadataConfiguration FederationMetadata
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public Models.Configuration.WSTrustConfiguration WSTrust
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public Models.Configuration.OAuth2Configuration OAuth2
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public Models.Configuration.OAuthWrapConfiguration OAuthWrap
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }
    }
}