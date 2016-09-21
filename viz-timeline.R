library(dplyr)
library(plyr)
library(ggplot2)

a <- read.csv("/Users/pmontgom/dev/depcon/conseq/state/timeline.log", as.is=T)
segment <- function(timestamps, labels) {
  timestamps <- as.double(strptime(timestamps, "%FT%T"))/60.0
  if(length(timestamps) == 1) {
    data.frame(start=timestamps, stop=timestamps, label=labels)
  } else {
    data.frame( start=timestamps[1:length(timestamps)-1], stop=timestamps[2:length(timestamps)], 
                label=labels[1:length(timestamps)-1] )
  }
}

#jobs.without.stop <- setdiff(unique(a$jobid), a$status %in% c("complete", "fail"))
#data.frame(jobid=, timestamp=max(a$timestamp))
aa <- ddply(a, 'jobid', function(x) { 
  z <- segment(x$timestamp, x$status) 
  z$jobid <- x$jobid[1]
  z })
aa$stop <- aa$stop - min(aa$start)
aa$start <- aa$start - min(aa$start)
aa$jobid <- as.factor(aa$jobid)

ggplot(aa[aa$start > 240,]) + aes(x=start, xend=stop, y=jobid, yend=jobid, size=3, color=label) + geom_segment()

head(aa[aa$jobid == 391,])

  
