using ApiTestServer.Filters.TestBasic.Filters;
using AuthorizationServer.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;

namespace AuthorizationServer.Controllers
{
    [ApiAuthorize]
    [InitializeSimpleMembership]
    public class ValuesController : ApiController
    {
        public string conn = ConfigurationManager.ConnectionStrings["DefaultConnection"].ToString();

        public List<string> Get()
        {
            return buscarCursos();
        }

        public List<string> buscarCursos()
        {
            List<string> lstCursos = new List<string>();

            using (SqlConnection connect = new SqlConnection(conn))
            {
                using (SqlCommand command = new SqlCommand("select * from ProviderAuthTest_TblCursos", connect))
                {
                    connect.Open();
                    SqlDataReader sqlReader = command.ExecuteReader();
                    if (sqlReader.HasRows)
                    {                        
                        while (sqlReader.Read())
                        {
                            string curso = Convert.ToString(sqlReader["NomeDoCurso"]);
                            lstCursos.Add(curso);
                        }
                    }
                }
            }
            return lstCursos;
        }
    }
}
