using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using MongoDB.Driver;
using MongoDB.Entities;

using NetCasbin.Model;
using NetCasbin.Persist;

namespace Geex.Common.Authorization.Casbin
{
    public class CasbinMongoAdapter : IAdapter
    {
        private IMongoCollection<CasbinRule> repository;
        public Func<IMongoCollection<CasbinRule>> RuleCollection { get; }

        public CasbinMongoAdapter(Func<IMongoCollection<CasbinRule>> ruleCollection)
        {
            RuleCollection = ruleCollection;
        }

        public void LoadPolicy(Model model)
        {
            this.repository = RuleCollection.Invoke();
            var list = repository.AsQueryable().ToList();
            LoadPolicyData(model, Helper.LoadPolicyLine, list);
        }

        public Task LoadPolicyAsync(Model model)
        {
            this.LoadPolicy(model);
            return Task.CompletedTask;
        }

        public async Task RemoveFilteredPolicyAsync(
            string ptype,
            int fieldIndex,
            params string[] fieldValues)
        {
            if (fieldValues == null || !fieldValues.Any())
                return;
            var line = new CasbinRule()
            {
                PType = ptype
            };
            var num = fieldValues.Count();
            if (fieldIndex <= 0 && 0 < fieldIndex + num)
                line.V0 = fieldValues[-fieldIndex];
            if (fieldIndex <= 1 && 1 < fieldIndex + num)
                line.V1 = fieldValues[1 - fieldIndex];
            if (fieldIndex <= 2 && 2 < fieldIndex + num)
                line.V2 = fieldValues[2 - fieldIndex];
            if (fieldIndex <= 3 && 3 < fieldIndex + num)
                line.V3 = fieldValues[3 - fieldIndex];
            if (fieldIndex <= 4 && 4 < fieldIndex + num)
                line.V4 = fieldValues[4 - fieldIndex];
            if (fieldIndex <= 5 && 5 < fieldIndex + num)
                line.V5 = fieldValues[5 - fieldIndex];
            var casbinRules = RuleCollection.Invoke().AsQueryable().Where(x =>
                ((fieldIndex <= 0 && 0 < fieldIndex + num && x.V0 == line.V0)
                 || (fieldIndex <= 1 && 1 < fieldIndex + num && x.V1 == line.V1)
                 || (fieldIndex <= 2 && 2 < fieldIndex + num && x.V2 == line.V2)
                 || (fieldIndex <= 3 && 3 < fieldIndex + num && x.V3 == line.V3)
                 || (fieldIndex <= 4 && 4 < fieldIndex + num && x.V4 == line.V4))
                && x.PType == ptype).ToList();
            var ruleIds = casbinRules.Select(x => x.Id);
            await repository.DeleteManyAsync(x =>ruleIds.Contains(x.Id));
        }

        public async Task SavePolicyAsync(Model model)
        {
            var source = new List<CasbinRule>();
            if (model.Model.ContainsKey("p"))
            {
                foreach (var keyValuePair in model.Model["p"])
                {
                    var key = keyValuePair.Key;
                    foreach (var stringList in keyValuePair.Value.Policy)
                    {
                        var casbinRule = savePolicyLine(key, stringList);
                        source.Add(casbinRule);
                    }
                }
            }
            if (model.Model.ContainsKey("g"))
            {
                foreach (var keyValuePair in model.Model["g"])
                {
                    var key = keyValuePair.Key;
                    foreach (var stringList in keyValuePair.Value.Policy)
                    {
                        var casbinRule = savePolicyLine(key, stringList);
                        source.Add(casbinRule);
                    }
                }
            }
            if (!source.Any())
                return;
            foreach (var x in source)
            {
                await x.ToDocument().SaveAsync();
            }
        }

        public void AddPolicy(string sec, string ptype, IList<string> rule)
        {
            this.AddPolicyAsync(ptype, rule).Wait();
        }

        public async Task AddPolicyAsync(string sec, string ptype, IList<string> rule)
        {
            await this.AddPolicyAsync(ptype, rule);
        }

        public void AddPolicies(string sec, string ptype, IEnumerable<IList<string>> rules)
        {
            foreach (var rule in rules)
            {
                this.AddPolicyAsync(ptype, rule).Wait();
            }
        }

        public async Task AddPoliciesAsync(string sec, string ptype, IEnumerable<IList<string>> rules)
        {
            this.AddPolicies(sec, ptype, rules);
        }

        public void RemovePolicy(string sec, string ptype, IList<string> rule)
        {
            RemoveFilteredPolicyAsync(ptype, 0, rule.ToArray()).Wait();
        }

        public Task RemovePolicyAsync(string sec, string ptype, IList<string> rule)
        {
            return RemoveFilteredPolicyAsync(ptype, 0, rule.ToArray());
        }

        public void RemovePolicies(string sec, string ptype, IEnumerable<IList<string>> rules)
        {
            foreach (var rule in rules)
            {
                RemoveFilteredPolicyAsync(ptype, 0, rule.ToArray()).Wait();
            }
        }

        public async Task RemovePoliciesAsync(string sec, string ptype, IEnumerable<IList<string>> rules)
        {
            foreach (var rule in rules)
            {
                await RemoveFilteredPolicyAsync(ptype, 0, rule.ToArray());
            }
        }

        public void RemoveFilteredPolicy(string sec, string ptype, int fieldIndex, params string[] fieldValues)
        {
            this.RemoveFilteredPolicyAsync(ptype, fieldIndex, fieldValues).Wait();
        }

        public async Task RemoveFilteredPolicyAsync(string sec, string ptype, int fieldIndex, params string[] fieldValues)
        {
            await this.RemoveFilteredPolicyAsync(ptype, fieldIndex, fieldValues);
        }

        public async Task AddPolicyAsync(string pType, IList<string> rule)
        {
            await savePolicyLine(pType, rule).ToDocument().SaveAsync();
        }

        private void LoadPolicyData(
            Model model,
            Helper.LoadPolicyLineHandler<string, Model> handler,
            IEnumerable<CasbinRule> rules)
        {
            foreach (var rule in rules)
                handler(GetPolicyCotent(rule), model);
        }

        private string GetPolicyCotent(CasbinRule rule)
        {
            var sb = new StringBuilder(rule.PType);
            Append(rule.V0);
            Append(rule.V1);
            Append(rule.V2);
            Append(rule.V3);
            Append(rule.V4);
            Append(rule.V5);
            return sb.ToString();

            void Append(string v)
            {
                if (string.IsNullOrEmpty(v))
                    return;
                sb.Append(", " + v);
            }
        }

        private CasbinRule savePolicyLine(string pType, IList<string> rule)
        {
            var casbinRule = new CasbinRule();
            casbinRule.PType = pType;
            if (rule.Count() > 0)
                casbinRule.V0 = rule[0];
            if (rule.Count() > 1)
                casbinRule.V1 = rule[1];
            if (rule.Count() > 2)
                casbinRule.V2 = rule[2];
            if (rule.Count() > 3)
                casbinRule.V3 = rule[3];
            if (rule.Count() > 4)
                casbinRule.V4 = rule[4];
            if (rule.Count() > 5)
                casbinRule.V5 = rule[5];
            return casbinRule;
        }

        public void SavePolicy(Model model)
        {
            this.SavePolicyAsync(model).Wait();
        }
    }
}