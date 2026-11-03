import {it,expect,vi} from 'vitest';
import {checkpointedPoll,singleFlight} from './runtime-security.js';
it('retries failed checkpoint recovery before reading any source',async()=>{
 const hydrate=vi.fn().mockRejectedValueOnce(new Error('API starting')).mockResolvedValue(undefined);
 const poll=vi.fn().mockResolvedValue(undefined);
 const run=singleFlight(checkpointedPoll(hydrate,poll));
 await expect(run()).rejects.toThrow('API starting');expect(poll).not.toHaveBeenCalled();
 await run();await run();expect(hydrate).toHaveBeenCalledTimes(2);expect(poll).toHaveBeenCalledTimes(2);
});
