<template>
  <div class="app-wrapper">
    <!-- Top Navigation Bar -->
    <header class="app-header">
      <div class="header-inner">
        <div class="brand">
          <span class="logo-icon">🤖</span>
          <h1 class="app-title">个人 Agent 申领与管理系统</h1>
        </div>
        <div class="user-profile">
          <div class="avatar">{{ name.charAt(0).toUpperCase() }}</div>
          <span class="username">{{ name }}</span>
        </div>
      </div>
    </header>

    <main class="app-content">
      <!-- User Information Section -->
      <el-card class="box-card section-card" shadow="hover">
        <template #header>
          <div class="card-header">
            <span class="header-title">👤 用户基本信息</span>
          </div>
        </template>
        <el-form label-position="top" size="default">
          <el-row :gutter="20">
            <el-col :span="12"><el-form-item label="姓名"><el-input v-model="name" placeholder="请输入姓名" /></el-form-item></el-col>
            <el-col :span="12"><el-form-item label="ID"><el-input v-model="idnum" placeholder="请输入ID" /></el-form-item></el-col>
            <el-col :span="12"><el-form-item label="身份证号"><el-input v-model="idcard" placeholder="请输入身份证号" /></el-form-item></el-col>
            <el-col :span="12"><el-form-item label="Email"><el-input v-model="email" placeholder="请输入邮箱" /></el-form-item></el-col>
            <el-col :span="12"><el-form-item label="Passport"><el-input v-model="passport" placeholder="请输入护照号" /></el-form-item></el-col>
            <el-col :span="12">
              <el-form-item label="人脸照片">
                <div class="file-upload-wrapper">
                  <input ref="picfile" type="file" accept="image/*" class="custom-file-input" />
                </div>
              </el-form-item>
            </el-col>
          </el-row>
        </el-form>
      </el-card>

      <!-- Agent Configuration Process -->
      <el-card class="box-card section-card" shadow="hover">
        <template #header>
          <div class="card-header">
            <span class="header-title">🚀 配置个人智能体流程</span>
          </div>
        </template>
        <el-timeline class="custom-timeline">
          <!-- Step 1: Request PHC -->
          <el-timeline-item :type="statusType(1)" :color="statusColor(1)" :hollow="stage < 1">
            <div class="timeline-content">
              <h3 class="step-title">1. 请求 PHC</h3>
              <div class="action-area">
                <el-button text bg size="small" @click="toggleShow('phc')">
                  {{ showPhc ? '收起详情' : '查看详情' }}
                </el-button>
                <el-button type="primary" :disabled="stage>1" :loading="loadingIssue" @click="issue" round>
                  请求 PHC
                </el-button>
                <el-tag type="success" effect="dark" v-if="successIssue" class="status-tag">成功</el-tag>
              </div>
            </div>
            <div v-if="showPhc" class="detail-box">
              <pre>{{ phcText || '暂无数据' }}</pre>
            </div>
          </el-timeline-item>

          <!-- Step 2: Select Configuration -->
          <el-timeline-item :type="statusType(2)" :color="statusColor(2)" :hollow="stage < 2">
            <div class="timeline-content">
              <h3 class="step-title">2. 选择 PA 的配置信息</h3>
              <div class="action-area">
                <el-button type="primary" :disabled="!canFetchCmm || stage>2" :loading="loadingCmm" @click="fetchcmm" round>
                  加载配置
                </el-button>
                <el-tag type="success" effect="dark" v-if="successCmm" class="status-tag">成功</el-tag>
              </div>
            </div>
            <div id="cmm_ui" v-html="cmmHtml" class="dynamic-form-area"></div>
          </el-timeline-item>

          <!-- Step 3: Submit Configuration -->
          <el-timeline-item :type="statusType(3)" :color="statusColor(3)" :hollow="stage < 3">
            <div class="timeline-content">
              <h3 class="step-title">3. 提交 PA 的配置信息</h3>
              <div class="action-area">
                <el-button text bg size="small" @click="toggleShow('pa')">
                  {{ showPa ? '收起详情' : '查看详情' }}
                </el-button>
                <el-button type="primary" :disabled="!canSubmitCmc || stage>3" :loading="loadingSubmit" @click="submitcmc" round>
                  提交配置
                </el-button>
                <el-tag type="success" effect="dark" v-if="successSubmit" class="status-tag">成功</el-tag>
              </div>
            </div>
            <div v-if="showPa" class="detail-box">
              <pre>{{ paCmmText || '暂无数据' }}</pre>
            </div>
          </el-timeline-item>

          <!-- Step 4: Create Agent -->
          <el-timeline-item :type="statusType(4)" :color="statusColor(4)" :hollow="stage < 4">
            <div class="timeline-content">
              <h3 class="step-title">4. 创建个人智能体</h3>
              <div class="action-area">
                <el-button text bg size="small" @click="toggleShow('agent')">
                  {{ showAgent ? '收起详情' : '查看详情' }}
                </el-button>
                <el-button type="success" :disabled="!canCreateAgent || stage>4" :loading="loadingCreate" @click="createAgent" round>
                  立即创建
                </el-button>
                <el-tag type="success" effect="dark" v-if="successCreate" class="status-tag">成功</el-tag>
              </div>
            </div>
            <div v-if="showAgent" class="detail-box">
              <pre>{{ agentOut || '暂无数据' }}</pre>
            </div>
          </el-timeline-item>
        </el-timeline>
      </el-card>

      <!-- Update Configuration -->
      <el-card class="box-card section-card" shadow="hover">
        <template #header>
          <div class="card-header">
            <span class="header-title">🔄 更新 PA 配置</span>
          </div>
        </template>
        <div class="update-actions">
          <div class="action-group">
            <el-button :disabled="!canFetchCmm" :loading="loadingUpdateInit" @click="updatepa" plain type="primary">
              1. 获取配置
            </el-button>
            <el-tag type="success" effect="plain" v-if="successUpdateInit">已获取</el-tag>
          </div>
          <div class="arrow-divider">➜</div>
          <div class="action-group">
            <el-button type="primary" :disabled="!canSubmitUpdate" :loading="loadingUpdateSubmit" @click="submitUpdate" round>
              2. 提交更新
            </el-button>
            <el-tag type="success" effect="dark" v-if="successUpdateSubmit">更新成功</el-tag>
          </div>
        </div>
        
        <div id="upd_cmm_ui" v-html="updCmmHtml" class="dynamic-form-area" style="margin-top: 20px;"></div>
        
        <transition name="el-fade-in">
          <div v-if="updateText" class="result-section">
            <el-divider content-position="left">更新结果详情</el-divider>
            <div class="result-header">
              <span class="result-label">服务器返回信息</span>
              <el-button text bg size="small" @click="toggleShow('update')">
                {{ showUpdate ? '收起' : '展开' }}
              </el-button>
            </div>
            <div v-show="showUpdate" class="detail-box">
              <pre>{{ updateText }}</pre>
            </div>
          </div>
        </transition>
      </el-card>

      <!-- Recovery Section -->
      <el-card class="box-card section-card warning-card" shadow="hover">
        <template #header>
          <div class="card-header warning-header">
            <span class="header-title">🛠️ 故障恢复 (Recovery)</span>
          </div>
        </template>
        
        <div class="recovery-item">
          <div class="recovery-info">
            <h4>PHC 与 PA 都丢失</h4>
            <p class="sub-text">当本地存储完全丢失时使用此选项</p>
          </div>
          <div class="recovery-actions">
            <el-button type="warning" :loading="loadingRecoverBoth" @click="recoverboth" plain>
              恢复 PHC & PA
            </el-button>
            <el-tag type="success" effect="dark" v-if="successRecoverBoth">成功</el-tag>
            <el-button text bg size="small" v-if="paRecoverBothText" @click="toggleShow('recoverBoth')">
              {{ showRecoverBoth ? '收起' : '展开详情' }}
            </el-button>
          </div>
          <div v-if="showRecoverBoth && paRecoverBothText" class="detail-box">
            <pre>{{ paRecoverBothText }}</pre>
          </div>
        </div>

        <el-divider></el-divider>

        <div class="recovery-item">
          <div class="recovery-info">
            <h4>仅 PA 丢失 (已有 PHC)</h4>
            <p class="sub-text">当保留了 PHC 但丢失了 Agent 文件时使用</p>
          </div>
          <div class="recovery-actions">
            <el-button type="warning" :disabled="!canRecoverPa" :loading="loadingRecoverPa" @click="recoverpa" plain>
              仅恢复 PA
            </el-button>
            <el-tag type="success" effect="dark" v-if="successRecoverPa">成功</el-tag>
            <el-button text bg size="small" v-if="paRecoverPaText" @click="toggleShow('recoverPa')">
              {{ showRecoverPa ? '收起' : '展开详情' }}
            </el-button>
          </div>
          <div v-if="showRecoverPa && paRecoverPaText" class="detail-box">
            <pre>{{ paRecoverPaText }}</pre>
          </div>
        </div>
      </el-card>
    </main>
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
      showPhc: false,
      showPa: false,
      showAgent: false,
      showUpdate: false,
      showRecoverBoth: false,
      showRecoverPa: false,
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
      const zhCat=['功能','输入','推理','知识','输出','外观'];
      const zhLabelMap={'text':'文本','voice':'语音','image':'图像','video':'视频','sensor':'传感器','system-event':'系统事件','rule-engine':'规则引擎','bayesian-net':'贝叶斯网络','fuzzy-logic':'模糊逻辑','llm':'大模型','retrieval':'检索','neural-network':'神经网络','planner':'规划','safety-filter':'安全过滤','local-memory':'本地记忆','long-term-memory':'长期记忆','vector-index':'向量索引','knowledge-base':'知识库','shared-org-data':'组织共享数据','browser':'浏览器','external-api':'外部API','database':'数据库','blockchain':'区块链','ipfs':'IPFS','iot-device':'物联网设备','cloud-storage':'云存储','speech':'语音','notification':'通知','json-api':'JSON API','actuation':'执行'};
      const zhLabelMapExtra={'text-processing':'文本处理','news-search':'新闻查询','payment':'支付','web-browsing':'联网搜索','rag-openai':'RAG+OPENAI','rag-deepseek':'RAG+deepseek','knowledge-pro':'专业知识库','ppt':'ppt','appearance-purple':'紫色','appearance-blue':'蓝色','appearance-pink':'粉色','appearance-green':'绿色'};
      const htmlRows=(this.cmmObj||[]).map((row,i)=>{ const isAppearanceRow = row.some(opt=>{ const val=String((opt && (opt.label??opt.id))||'').toLowerCase().replace(/\s+/g,''); return val.includes('appearance'); }); const cat = isAppearanceRow ? '外观' : (zhCat[i] || '其他配置'); const inputType = isAppearanceRow ? 'radio' : 'checkbox'; const opts=row.map((opt,j)=>{ const raw = (opt && (opt.label??opt.id)) ? String(opt.label??opt.id) : ''; const norm = raw.toLowerCase().trim().replace(/\s+/g,'').replace(/_/g,'-'); let label = zhLabelMap[norm] || zhLabelMapExtra[norm] || zhLabelMap[raw] || zhLabelMapExtra[raw]; if(!label && (norm.includes('appearance') || isAppearanceRow)){ if(norm.includes('purple')) label='紫色'; else if(norm.includes('blue')) label='蓝色'; else if(norm.includes('pink')) label='粉色'; else if(norm.includes('green')) label='绿色'; } if(!label) label = raw ? raw : '未定义'; return `<label class="option-chip"><input type="${inputType}" name="row_${i}" value="${j}"><span class="chip-content">${label}</span></label>`; }).join(' '); return `<div class="config-category"><div class="config-group-title">${cat}</div><div class="config-options">${opts}</div></div>`; }).join('');
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
        const zhCat=['功能','输入','推理','知识','输出','外观'];
        const zhLabelMap={'text':'文本','voice':'语音','image':'图像','video':'视频','sensor':'传感器','system-event':'系统事件','rule-engine':'规则引擎','bayesian-net':'贝叶斯网络','fuzzy-logic':'模糊逻辑','llm':'大模型','retrieval':'检索','neural-network':'神经网络','planner':'规划','safety-filter':'安全过滤','local-memory':'本地记忆','long-term-memory':'长期记忆','vector-index':'向量索引','knowledge-base':'知识库','shared-org-data':'组织共享数据','browser':'浏览器','external-api':'外部API','database':'数据库','blockchain':'区块链','ipfs':'IPFS','iot-device':'物联网设备','cloud-storage':'云存储','speech':'语音','notification':'通知','json-api':'JSON API','actuation':'执行'};
        const zhLabelMapExtra={'text-processing':'文本处理','news-search':'新闻查询','payment':'支付','web-browsing':'联网搜索','rag-openai':'RAG+OPENAI','rag-deepseek':'RAG+deepseek','knowledge-pro':'专业知识库','ppt':'ppt','appearance-purple':'紫色','appearance-blue':'蓝色','appearance-pink':'粉色','appearance-green':'绿色'};
        const htmlRows=(cmm||[]).map((row,i)=>{ const isAppearanceRow = row.some(opt=>{ const val=String((opt && (opt.label??opt.id))||'').toLowerCase().replace(/\s+/g,''); return val.includes('appearance'); }); const cat = isAppearanceRow ? '外观' : (zhCat[i] || '其他配置'); const inputType = isAppearanceRow ? 'radio' : 'checkbox'; const opts=row.map((opt,j)=>{ const raw = (opt && (opt.label??opt.id)) ? String(opt.label??opt.id) : ''; const norm = raw.toLowerCase().trim().replace(/\s+/g,'').replace(/_/g,'-'); let label = zhLabelMap[norm] || zhLabelMapExtra[norm] || zhLabelMap[raw] || zhLabelMapExtra[raw]; if(!label && (norm.includes('appearance') || isAppearanceRow)){ if(norm.includes('purple')) label='紫色'; else if(norm.includes('blue')) label='蓝色'; else if(norm.includes('pink')) label='粉色'; else if(norm.includes('green')) label='绿色'; } if(!label) label = raw ? raw : '未定义'; return `<label class="option-chip"><input type="${inputType}" name="upd_row_${i}" value="${j}"><span class="chip-content">${label}</span></label>`; }).join(' '); return `<div class="config-category"><div class="config-group-title">${cat}</div><div class="config-options">${opts}</div></div>`; }).join('');
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
:root {
  --primary-color: #409EFF;
  --header-bg: #fff;
  --header-height: 64px;
  --content-width: 1100px;
}

body {
  margin: 0;
  background-color: #f5f7fa;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}

.app-wrapper {
  min-height: 100vh;
  background: linear-gradient(120deg, #89f7fe 0%, #66a6ff 100%);
}

/* Header Styles */
.app-header {
  height: var(--header-height);
  background: var(--header-bg);
  box-shadow: 0 2px 8px rgba(0,0,0,0.05);
  position: sticky;
  top: 0;
  z-index: 100;
  display: flex;
  justify-content: center;
}

.header-inner {
  width: 100%;
  max-width: var(--content-width);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 20px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
}

.logo-icon {
  font-size: 28px;
}

.app-title {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
  color: #303133;
}

.user-profile {
  display: flex;
  align-items: center;
  gap: 10px;
}

.avatar {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: var(--primary-color);
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: bold;
}

.username {
  font-size: 14px;
  color: #606266;
  font-weight: 500;
}

/* Main Content Styles */
.app-content {
  max-width: var(--content-width);
  margin: 24px auto;
  padding: 0 20px;
}

.section-card {
  margin-bottom: 24px;
  border: none;
  border-radius: 8px;
  transition: all 0.3s ease;
}

.section-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 20px rgba(0,0,0,0.08) !important;
}

.card-header {
  display: flex;
  align-items: center;
  font-size: 16px;
  font-weight: 600;
  color: #303133;
}

.header-title {
  position: relative;
  padding-left: 0px;
}

/* Form Styles */
.file-upload-wrapper {
  border: 1px dashed #dcdfe6;
  padding: 10px;
  border-radius: 4px;
  background: #fafafa;
}

.custom-file-input {
  width: 100%;
}

/* Timeline Styles */
.custom-timeline {
  padding-left: 10px;
}

.timeline-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
}

.step-title {
  margin: 0;
  font-size: 15px;
  font-weight: 500;
  color: #303133;
}

.action-area {
  display: flex;
  align-items: center;
  gap: 12px;
}

.status-tag {
  min-width: 50px;
  text-align: center;
}

/* Dynamic Content Areas */
.detail-box {
  margin-top: 12px;
  background: #fafafa;
  border: 1px solid #e4e7ed;
  border-radius: 4px;
  padding: 12px;
}

pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-all;
  font-family: Consolas, Monaco, monospace;
  font-size: 12px;
  color: #606266;
}

.dynamic-form-area {
  margin-top: 16px;
  padding: 16px;
  background: #fdfdfd;
  border: 1px solid #ebeef5;
  border-radius: 6px;
}

/* Config Options Styles */
.config-category {
    margin-bottom: 20px;
    background: #eef5fe;
    padding: 15px;
    border-radius: 8px;
    border: 1px solid #d9ecff;
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.02);
}
.config-group-title {
    font-weight: 700;
    color: #409EFF;
    margin-bottom: 12px;
    font-size: 14px;
    display: flex;
    align-items: center;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.config-group-title::before {
    content: '';
    display: inline-block;
    width: 6px;
    height: 6px;
    background: #409EFF;
    margin-right: 8px;
    border-radius: 50%;
}
.config-options {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
}
.option-chip {
    position: relative;
    cursor: pointer;
    user-select: none;
}
.option-chip input {
    position: absolute;
    opacity: 0;
    width: 0;
    height: 0;
}
.chip-content {
    display: inline-block;
    padding: 8px 18px;
    background: #fff;
    color: #555;
    border-radius: 20px;
    font-size: 13px;
    border: 1px solid #e4e7ed;
    transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
    font-weight: 500;
}
.option-chip:hover .chip-content {
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    border-color: #c6e2ff;
    color: #409EFF;
}
.option-chip input:checked + .chip-content {
    background: #409EFF;
    color: #fff;
    border-color: #409EFF;
    box-shadow: 0 4px 12px rgba(64, 158, 255, 0.4);
    transform: translateY(-1px);
}

/* Update Section Styles */
.update-actions {
  display: flex;
  align-items: center;
  gap: 16px;
  background: #f5f7fa;
  padding: 16px;
  border-radius: 6px;
}

.action-group {
  display: flex;
  align-items: center;
  gap: 8px;
}

.arrow-divider {
  color: #909399;
  font-weight: bold;
}

.result-section {
  margin-top: 24px;
}

.result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.result-label {
  font-size: 14px;
  color: #909399;
}

/* Recovery Section Styles */
.warning-card {
  /* Removed border */
}

.warning-header {
  /* Removed color */
}

.recovery-item {
  padding: 8px 0;
}

.recovery-info h4 {
  margin: 0 0 4px 0;
  font-size: 15px;
  color: #303133;
}

.sub-text {
  margin: 0 0 12px 0;
  font-size: 12px;
  color: #909399;
}

.recovery-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}
</style>
