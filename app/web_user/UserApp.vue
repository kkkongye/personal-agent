<template>
  <div style="max-width: 980px; margin: 0 auto">
    <el-card shadow="hover" style="margin-bottom:16px">
      <div style="display:flex; align-items:center; justify-content:space-between">
        <div style="font-size:18px; font-weight:600">用户侧配置个人智能体</div>
        <!-- <div style="display:flex; gap:8px">
          <el-input v-model="tpBase" placeholder="TP Base" style="width:240px" />
          <el-input v-model="apBase" placeholder="AP Base" style="width:240px" />
        </div> -->
      </div>
    </el-card>

    <el-card shadow="never" style="margin-bottom:16px">
      <el-form label-position="right" label-width="90px">
        <el-row :gutter="8">
          <el-col :span="12"><el-form-item label="姓名"><el-input v-model="name" /></el-form-item></el-col>
          <el-col :span="12"><el-form-item label="ID"><el-input v-model="idnum" /></el-form-item></el-col>
          <el-col :span="12"><el-form-item label="身份证号"><el-input v-model="idcard" /></el-form-item></el-col>
          <el-col :span="12"><el-form-item label="Email"><el-input v-model="email" /></el-form-item></el-col>
          <el-col :span="12"><el-form-item label="Passport"><el-input v-model="passport" /></el-form-item></el-col>
          <el-col :span="12"><el-form-item label="人脸照片"><input ref="picfile" type="file" accept="image/*" /></el-form-item></el-col>
        </el-row>
      </el-form>
    </el-card>

    <el-card shadow="never" style="margin-bottom:16px">
      <div style="font-weight:600; margin-bottom:8px">配置个人智能体流程进度</div>
      <el-timeline style="max-width: 800px">
        <el-timeline-item :type="statusType(1)" :color="statusColor(1)" :hollow="false">
          <div style="display:flex; align-items:center; justify-content:space-between">
            <div>1. 请求 PHC</div>
            <div style="display:flex; gap:8px; align-items:center">
              <el-button text size="small" @click="toggleShow('phc')">{{ showPhc ? '收起' : '展开' }}</el-button>
              <el-button type="primary" :disabled="stage>1" :loading="loadingIssue" @click="issue">请求</el-button>
              <el-tag type="success" v-if="successIssue">成功</el-tag>
            </div>
          </div>
          <pre v-if="showPhc" style="margin-top:8px">{{ phcText }}</pre>
        </el-timeline-item>

        <el-timeline-item :type="statusType(2)" :color="statusColor(2)" :hollow="false">
          <div style="display:flex; align-items:center; justify-content:space-between">
            <div>2. 选择 PA 的配置信息</div>
            <div style="display:flex; gap:8px; align-items:center">
              <el-button type="primary" :disabled="!canFetchCmm || stage>2" :loading="loadingCmm" @click="fetchcmm">选择</el-button>
              <el-tag type="success" v-if="successCmm">成功</el-tag>
            </div>
          </div>
          <div id="cmm_ui" v-html="cmmHtml" style="margin-top:8px"></div>
        </el-timeline-item>

        <el-timeline-item :type="statusType(3)" :color="statusColor(3)" :hollow="false">
          <div style="display:flex; align-items:center; justify-content:space-between">
            <div>3.提交 PA 的配置信息</div>
            <div style="display:flex; gap:8px; align-items:center">
              <el-button text size="small" @click="toggleShow('pa')">{{ showPa ? '收起' : '展开' }}</el-button>
              <el-button type="primary" :disabled="!canSubmitCmc || stage>3" :loading="loadingSubmit" @click="submitcmc">提交</el-button>
              <el-tag type="success" v-if="successSubmit">成功</el-tag>
            </div>
          </div>
          <pre v-if="showPa" style="margin-top:8px">{{ paCmmText }}</pre>
        </el-timeline-item>

        <el-timeline-item :type="statusType(4)" :color="statusColor(4)" :hollow="false">
          <div style="display:flex; align-items:center; justify-content:space-between">
            <div>4. 创建个人智能体</div>
            <div style="display:flex; gap:8px; align-items:center">
              <el-button text size="small" @click="toggleShow('agent')">{{ showAgent ? '收起' : '展开' }}</el-button>
              <el-button type="success" :disabled="!canCreateAgent || stage>4" :loading="loadingCreate" @click="createAgent">创建</el-button>
              <el-tag type="success" v-if="successCreate">成功</el-tag>
            </div>
          </div>
          <pre v-if="showAgent" style="margin-top:8px">{{ agentOut }}</pre>
        </el-timeline-item>
      </el-timeline>
    </el-card>

    <el-card shadow="hover" style="margin-bottom:16px">
      <div style="font-weight:600; margin-bottom:8px">更新 PA 的配置信息</div>
      <div style="display:flex; gap:8px; align-items:center; margin-bottom:8px">
        <el-button :disabled="!canFetchCmm" :loading="loadingUpdateInit" @click="updatepa">更新配置</el-button>
        <el-tag type="success" v-if="successUpdateInit">成功</el-tag>
        <el-button type="primary" :disabled="!canSubmitUpdate" :loading="loadingUpdateSubmit" @click="submitUpdate">提交更新</el-button>
        <el-tag type="success" v-if="successUpdateSubmit">成功</el-tag>
      </div>
      <div id="upd_cmm_ui" v-html="updCmmHtml" style="margin-bottom:8px"></div>
      <div style="display:flex; align-items:center; justify-content:space-between">
        <div style="font-weight:500">更新结果</div>
        <el-button text size="small" @click="toggleShow('update')">{{ showUpdate ? '收起' : '展开' }}</el-button>
      </div>
      <pre v-if="showUpdate">{{ updateText }}</pre>
    </el-card>

    <el-card shadow="hover" style="margin-bottom:16px">
      <div style="display:flex; align-items:center; justify-content:space-between; font-weight:600; margin-bottom:8px">
        <div>PHC 与 PA 都丢失，恢复PA</div>
        <el-button text size="small" @click="toggleShow('recoverBoth')">{{ showRecoverBoth ? '收起' : '展开' }}</el-button>
      </div>
      <div style="display:flex; gap:8px; align-items:center">
        <el-button type="warning" :loading="loadingRecoverBoth" @click="recoverboth">恢复 PHC 与 PA</el-button>
        <el-tag type="success" v-if="successRecoverBoth">成功</el-tag>
      </div>
      <pre v-if="showRecoverBoth" style="margin-top:8px">{{ paRecoverBothText }}</pre>
    </el-card>

    <el-card shadow="hover" style="margin-bottom:16px">
      <div style="display:flex; align-items:center; justify-content:space-between; font-weight:600; margin-bottom:8px">
        <div>PA 丢失，恢复PA</div>
        <el-button text size="small" @click="toggleShow('recoverPa')">{{ showRecoverPa ? '收起' : '展开' }}</el-button>
      </div>
      <div style="display:flex; gap:8px; align-items:center">
        <el-button type="warning" :disabled="!canRecoverPa" :loading="loadingRecoverPa" @click="recoverpa">恢复 PA</el-button>
        <el-tag type="success" v-if="successRecoverPa">成功</el-tag>
      </div>
      <pre v-if="showRecoverPa" style="margin-top:8px">{{ paRecoverPaText }}</pre>
    </el-card>
  </div>
</template>

<script>
export default {
  name: 'UserApp',
  data(){
    return {
      tpBase: 'http://127.0.0.1:8001',
      apBase: 'http://127.0.0.1:8002',
      name: 'Alice', idnum: 'ID123', idcard: 'IDCARD123456', email: 'alice@example.com', passport: 'P123456789',
      phcObj: null, paObj: null, cmmObj: null, cmcObj: null,
      phcText: '', paCmmText: '', hashCH: '', hashCCH: '', hashStatus: '', paRecoverPaText: '', paRecoverBothText: '', updateText: '', agentOut: '',
      canFetchCmm: false, canCreateAgent: false, canRecoverPa: false, canSubmitCmc: false, canSubmitUpdate: false,
      cmmSk: '', cmmPk: '', updSk: '', updPk: '', lastCMM: null,
      cmmHtml: '', updCmmHtml: '',
      stage: 0,
      showPhc: true,
      showPa: true,
      showAgent: true,
      showUpdate: true,
      showRecoverBoth: true,
      showRecoverPa: true,
      loadingIssue: false,
      loadingCmm: false,
      loadingSubmit: false,
      loadingCreate: false,
      loadingUpdateInit: false,
      loadingUpdateSubmit: false,
      loadingRecoverBoth: false,
      loadingRecoverPa: false,
      successIssue: false,
      successCmm: false,
      successSubmit: false,
      successCreate: false,
      successUpdateInit: false,
      successUpdateSubmit: false,
      successRecoverBoth: false,
      successRecoverPa: false
    }
  },
  methods: {
    async issue(){
      this.loadingIssue = true;
      const f = this.$refs.picfile && this.$refs.picfile.files && this.$refs.picfile.files[0];
      if (!f) { this.phcText='请先选择照片再申请 PHC'; return; }
      const fd=new FormData(); fd.append('file', f);
      let picString=null;
      try {
        const rUpload=await fetch('/v1/pic/upload',{method:'POST',body:fd});
        const dUpload=await rUpload.json();
        picString = dUpload.string_part || null;
        if (!picString) { this.phcText='图片上传失败，请重试'; return; }
      } catch (e) { this.phcText='图片上传失败：'+(e&&e.message?e.message:'unknown'); return; }
      const user={pii:{name:this.name,id_number:this.idnum,id_card_number:(this.idcard||''),email:this.email},bi:{last_login_ip:'127.0.0.1',passport_number:(this.passport||''),pic_string:picString},cdid:'cdid:user.placeholder',ecid:'g'};
      const payload={base_url:this.tpBase,user};
      try{
        const r=await fetch('/user/request_phc',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
        const data=await r.json(); this.phcObj = data.phc || data.PHC || null; this.phcText=JSON.stringify(data,null,2); this.canFetchCmm=!!this.phcObj; this.canRecoverPa=!!this.phcObj; this.stage = 1; this.successIssue = true;
      }catch(e){ this.phcText='Request PHC failed: '+(e&&e.message?e.message:'unknown'); }
      finally { this.loadingIssue = false; }
    },
    async fetchcmm(){
      this.loadingCmm = true;
      const user={pii:{name:this.name,id_number:this.idnum,id_card_number:(this.idcard||''),email:this.email},bi:{last_login_ip:'127.0.0.1',passport_number:(this.passport||'')},cdid:'cdid:user.placeholder',ecid:'g'};
      const r=await fetch('/user/cmm_init',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({base_url:this.apBase, phc:this.phcObj, user})});
      const data=await r.json(); this.cmmObj=data.cmm; this.cmcObj=(this.cmmObj||[]).map(row=>row[0]); this.cmmSk=String(data.sk||""); this.cmmPk=String(data.pk||"");
      const zhCat=['功能','输入','推理','知识','输出'];
      const zhLabelMap={'text':'文本','voice':'语音','image':'图像','video':'视频','sensor':'传感器','system-event':'系统事件','rule-engine':'规则引擎','bayesian-net':'贝叶斯网络','fuzzy-logic':'模糊逻辑','llm':'大模型','retrieval':'检索','neural-network':'神经网络','planner':'规划','safety-filter':'安全过滤','local-memory':'本地记忆','long-term-memory':'长期记忆','vector-index':'向量索引','knowledge-base':'知识库','shared-org-data':'组织共享数据','browser':'浏览器','external-api':'外部API','database':'数据库','blockchain':'区块链','ipfs':'IPFS','iot-device':'物联网设备','cloud-storage':'云存储','speech':'语音','notification':'通知','json-api':'JSON API','actuation':'执行'};
      const zhLabelMapExtra={'text-processing':'文本处理','news-search':'新闻查询','payment':'支付','web-browsing':'联网搜索','rag-openai':'RAG+OPENAI','rag-deepseek':'RAG+deepseek','knowledge-pro':'专业知识库','ppt':'ppt'};
      const htmlRows=(this.cmmObj||[]).map((row,i)=>{ const opts=row.map((opt,j)=>`<label><input type=checkbox name=\"row_${i}\" value='${j}'>${(zhLabelMap[opt.label]||zhLabelMapExtra[opt.label]||opt.label)}</label>`).join(' '); return `<div style='margin:6px 0'>${zhCat[i]}：${opts}</div>`; }).join('');
      this.cmmHtml = htmlRows; this.canSubmitCmc = !!(this.cmmSk && this.cmmPk); this.stage = 2; this.loadingCmm = false; this.successCmm = true;
    },
    async submitcmc(){
      this.loadingSubmit = true;
      const hid = this.idnum? this.idnum : '';
      const cmc = (this.cmmObj||[]).map((row,i)=>{ const nodes = Array.from(document.querySelectorAll(`input[name='row_${i}']:checked`)); const idxs = nodes.map(n=>Number(n.value)); return row.filter((_,j)=>idxs.includes(j)); });
      this.cmcObj = cmc;
      const r=await fetch('/user/cmm_submit',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({base_url:this.apBase, cmc:cmc||[], hid:hid, phc:this.phcObj, user_sk: this.cmmSk||"", user_pk: this.cmmPk||""})});
      const data=await r.json();
      this.paCmmText=JSON.stringify(data,null,2);
      this.hashCH = '';
      this.hashCCH = '';
      this.hashStatus = '';
      this.phcObj = data.PHC; this.paObj = data.PA; this.canCreateAgent = !!(this.phcObj && this.paObj); this.stage = 3; this.successSubmit = true;
      this.loadingSubmit = false;
    },
    async createAgent(){
      this.loadingCreate = true;
      const payload2 = { phc: this.phcObj||{}, pa: this.paObj||{}, cmc: this.cmcObj||[] };
      const r2=await fetch('/user/create_agent',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload2)});
      const data2=await r2.json(); this.agentOut=JSON.stringify(data2,null,2); this.stage = 4; this.loadingCreate = false; this.successCreate = true;
    },
    async recoverpa(){
      this.loadingRecoverPa = true;
      const user={pii:{name:this.name,id_number:this.idnum,id_card_number:(this.idcard||''),email:this.email},bi:{last_login_ip:'127.0.0.1',passport_number:(this.passport||'')},cdid:'cdid:user.placeholder',ecid:'g'};
      const payload={base_url:this.apBase, phc:this.phcObj, user};
      try{
        const r=await fetch('/user/recover_pa',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
        const data=await r.json(); this.paRecoverPaText=JSON.stringify(data,null,2); this.successRecoverPa = true;
      }catch(e){ this.paRecoverText='Recover PA failed: '+(e&&e.message?e.message:'unknown'); }
      finally { this.loadingRecoverPa = false; }
    },
    async recoverboth(){
      this.loadingRecoverBoth = true;
      const user={pii:{name:this.name,id_number:this.idnum,id_card_number:(this.idcard||''),email:this.email},bi:{last_login_ip:'127.0.0.1',passport_number:(this.passport||'')},cdid:'cdid:user.placeholder',ecid:'g'};
      try {
        const r=await fetch('/user/recover_both',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({tp_base:this.tpBase, ap_base:this.apBase, user})});
        const data=await r.json(); this.paRecoverBothText=JSON.stringify(data,null,2); this.phcObj = data.phc || null; this.successRecoverBoth = true;
      }catch(e){ this.paRecoverText='Recover Both failed: '+(e&&e.message?e.message:'unknown'); }
      finally { this.loadingRecoverBoth = false; }
    },
    async updatepa(){
      this.loadingUpdateInit = true;
      const user={pii:{name:this.name,id_number:this.idnum,id_card_number:(this.idcard||''),email:this.email},bi:{last_login_ip:'127.0.0.1',passport_number:(this.passport||'')},cdid:'cdid:user.placeholder',ecid:'g'};
      if(!this.phcObj){ this.updateText='请先点击 1.Request PHC'; return; }
      try{
        const r=await fetch('/user/update_init',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({base_url:this.apBase, phc:this.phcObj, user})});
        const data=await r.json(); const cmm=data.cmm; this.updSk=String(data.sk||""); this.updPk=String(data.pk||""); this.lastCMM=cmm; this.successUpdateInit = true;
        const zhCat=['功能','输入','推理','知识','输出'];
        const zhLabelMap={'text':'文本','voice':'语音','image':'图像','video':'视频','sensor':'传感器','system-event':'系统事件','rule-engine':'规则引擎','bayesian-net':'贝叶斯网络','fuzzy-logic':'模糊逻辑','llm':'大模型','retrieval':'检索','neural-network':'神经网络','planner':'规划','safety-filter':'安全过滤','local-memory':'本地记忆','long-term-memory':'长期记忆','vector-index':'向量索引','knowledge-base':'知识库','shared-org-data':'组织共享数据','browser':'浏览器','external-api':'外部API','database':'数据库','blockchain':'区块链','ipfs':'IPFS','iot-device':'物联网设备','cloud-storage':'云存储','speech':'语音','notification':'通知','json-api':'JSON API','actuation':'执行'};
        const zhLabelMapExtra={'text-processing':'文本处理','news-search':'新闻查询','payment':'支付','web-browsing':'联网搜索','rag-openai':'RAG+OPENAI','rag-deepseek':'RAG+deepseek','knowledge-pro':'专业知识库','ppt':'ppt'};
        const htmlRows=(cmm||[]).map((row,i)=>{ const opts=row.map((opt,j)=>`<label><input type=checkbox name=\"upd_row_${i}\" value='${j}'>${(zhLabelMap[opt.label]||zhLabelMapExtra[opt.label]||opt.label)}</label>`).join(' '); return `<div style='margin:6px 0'>${zhCat[i]}：${opts}</div>`; }).join('');
        this.updCmmHtml = htmlRows; this.canSubmitUpdate = !!((cmm && cmm.length>0) && (this.updSk && this.updPk));
      }catch(e){ this.updateText='Update PA failed: '+(e&&e.message?e.message:'unknown'); }
      finally { this.loadingUpdateInit = false; }
    },
    async submitUpdate(){
      this.loadingUpdateSubmit = true;
      const hid = this.idnum? this.idnum : '';
      const cmc = (this.lastCMM||[]).map((row,i)=>{ const nodes = Array.from(document.querySelectorAll(`input[name='upd_row_${i}']:checked`)); const idxs = nodes.map(n=>Number(n.value)); return row.filter((_,j)=>idxs.includes(j)); });
      const payload={base_url:this.apBase, cmc:cmc||[], hid:hid, phc:this.phcObj, user_sk: this.updSk||"", user_pk: this.updPk||""};
      const r=await fetch('/user/update_submit',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
      const data=await r.json(); this.updateText=JSON.stringify(data,null,2); this.successUpdateSubmit = true;
      this.loadingUpdateSubmit = false;
    },
    statusType(idx){
      if (this.stage>idx) return 'success';
      if (this.stage===idx) return 'primary';
      return '';
    },
    statusColor(idx){
      if (this.stage>idx) return '#67C23A';
      if (this.stage===idx) return '#409EFF';
      return '#C0C4CC';
    },
    toggleShow(which){
      if (which==='phc') this.showPhc = !this.showPhc;
      else if (which==='pa') this.showPa = !this.showPa;
      else if (which==='agent') this.showAgent = !this.showAgent;
      else if (which==='update') this.showUpdate = !this.showUpdate;
      else if (which==='recoverBoth') this.showRecoverBoth = !this.showRecoverBoth;
      else if (which==='recoverPa') this.showRecoverPa = !this.showRecoverPa;
    }
  }
}
</script>

<style>
pre{background:#f6f8fa;padding:12px;border:1px solid #e1e4e8;overflow:auto}
.el-form-item__label{padding-right:8px}
</style>
